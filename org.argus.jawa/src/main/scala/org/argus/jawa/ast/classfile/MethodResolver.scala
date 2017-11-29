/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.classfile

import org.argus.jawa.ast._
import org.argus.jawa.core.{AccessFlag, JawaType, Signature}
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.{Label, MethodVisitor}

class MethodResolver(
    api: Int,
    accessFlag: Int,
    signature: Signature,
    methods: MList[MethodDeclaration]) extends MethodVisitor(api) {
  val returnType: Type = new Type(signature.getReturnType)
  val methodSymbol: MethodDefSymbol = new MethodDefSymbol(signature.methodName)
  methodSymbol.signature = signature
  val params: MList[Param] = mlistEmpty
  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
    params += new Param(signature.getClassType, "this", List(new Annotation("kind", new TokenValue("this"))))
  }
  val annotations: IList[Annotation] = List(
    new Annotation("signature", SymbolValue(new SignatureSymbol(signature))(NoPosition)),
    new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
  )

  val locals: MList[LocalVarDeclaration] = mlistEmpty
  val locations: MList[Location] = mlistEmpty
  val catchClauses: MList[CatchClause] = mlistEmpty

  private var paramCounter = 0
  override def visitParameter(name: String, access: Int): Unit = {
    val typ: JawaType = signature.getParameterTypes.lift(paramCounter).getOrElse(throw DeBytecodeException(s"Sig: $signature does not have type for param num $paramCounter"))
    val annotations: IList[Annotation] = if(typ.isObject) {
      List(new Annotation("kind", new TokenValue("object")))
    } else {
      ilistEmpty
    }
    params += new Param(typ, name, annotations)
    paramCounter += 1
  }

  private var labelCount: Int = 0
  private var locCount: Int = 0
  private def line: Int = labelCount + locCount

  private val labels: MMap[Label, Location] = mmapEmpty

  private def createLabel(label: Label): Unit = {
    val l = s"Label$labelCount"
    val loc = new Location(l, EmptyStatement(mlistEmpty)(NoPosition))
    loc.locationSymbol.locationIndex = line
    labels(label) = loc
    locations += loc
    labelCount += 1
  }

  private def createLocation(stmt: Statement): Unit = {
    val l = s"L$locCount."
    val loc = new Location(l, stmt)
    loc.locationSymbol.locationIndex = line
    locations += loc
    locCount += 1
  }

  override def visitLabel(label: Label): Unit = {
    createLabel(label)
  }

  override def visitLineNumber(line: Int, start: Label): Unit = {
    labels.get(start) match {
      case Some(Location(_, EmptyStatement(annos))) =>
        annos += new Annotation("line", new TokenValue(s"$line"))
      case _ =>
    }
  }

  override def visitLocalVariable(
      name: FileResourceUri,
      desc: FileResourceUri,
      signature: FileResourceUri,
      start: Label,
      end: Label,
      index: Int): Unit = {

  }

  override def visitEnd(): Unit = {
    val body: Body = ResolvedBody(locals.toList, locations.toList, catchClauses.toList)(NoPosition)
    val md = MethodDeclaration(returnType, methodSymbol, params.toList, annotations, body)(NoPosition)
    md.getAllChildren foreach {
      case vd: VarDefSymbol => vd.owner = md
      case vs: VarSymbol => vs.owner = md
      case ld: LocationDefSymbol => ld.owner = md
      case ls: LocationSymbol => ls.owner = md
      case _ =>
    }
    methods += md
  }
}
