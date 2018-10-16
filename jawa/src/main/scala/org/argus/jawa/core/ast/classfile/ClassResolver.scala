/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements.AccessFlag.FlagKind
import org.argus.jawa.core.elements.{AccessFlag, JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util.{MList, mlistEmpty}
import org.objectweb.asm.{ClassVisitor, FieldVisitor, MethodVisitor}

class ClassResolver(api: Int) extends ClassVisitor(api) {

  var cityp: TypeDefSymbol = _
  val annotations: MList[Annotation] = mlistEmpty
  var extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses] = None
  val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
  val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
  val methods: MList[MethodDeclaration] = mlistEmpty
  def cid: ClassOrInterfaceDeclaration = {
    ClassOrInterfaceDeclaration(
      cityp,
      annotations.toList,
      extendsAndImplementsClausesOpt,
      instanceFields.toList,
      staticFields.to,
      methods.toList)(NoPosition)
  }

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  override def visit(
      version: Int,
      access: Int,
      name: String,
      signature: String,
      superName: String,
      interfaces: Array[String]): Unit = {
    cityp = new TypeDefSymbol(getClassName(name))

    val accessFlag: Int = AccessFlag.getJawaFlags(access, FlagKind.CLASS, isConstructor = false)
    val kind = if(AccessFlag.isInterface(accessFlag)) {
      "interface"
    } else {
      "class"
    }
    annotations += new Annotation("kind", new TokenValue(kind))
    annotations += new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))

    val parentTyps: MList[ExtendAndImplement] = mlistEmpty
    Option(superName) match {
      case Some(sn) =>
        val annotation = new Annotation("kind", new TokenValue("class"))
        parentTyps += ExtendAndImplement(new TypeSymbol(getClassName(sn)), List(annotation))(NoPosition)
      case None =>
    }
    for(interface <- interfaces) {
      val annotation = new Annotation("kind", new TokenValue("interface"))
      parentTyps += ExtendAndImplement(new TypeSymbol(getClassName(interface)), List(annotation))(NoPosition)
    }
    if(parentTyps.nonEmpty) {
      extendsAndImplementsClausesOpt = Some(ExtendsAndImplementsClauses(parentTyps.toList)(NoPosition))
    }
  }

  override def visitField(
      access: Int,
      name: String,
      desc: String,
      signature: String,
      value: Object): FieldVisitor = {
    val accessFlag: Int = AccessFlag.getJawaFlags(access, FlagKind.FIELD, isConstructor = false)
    val typ: JawaType = JavaKnowledge.formatSignatureToType(desc)
    val fieldType = new Type(typ.baseTyp, typ.dimensions, NoPosition)
    val annotation = new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
    val fieldName = s"${cityp.typ.jawaName}.$name"
    if(AccessFlag.isStatic(accessFlag)) {
      val field = new FieldDefSymbol(s"@@$fieldName")
      staticFields += StaticFieldDeclaration(fieldType, field, List(annotation))(NoPosition)
    } else {
      val field = new FieldDefSymbol(fieldName)
      instanceFields += InstanceFieldDeclaration(fieldType, field, List(annotation))(NoPosition)
    }
    null
  }

  override def visitMethod(access: Int, name: String, desc: String,
                           signature: String, exceptions: scala.Array[String]): MethodVisitor = {
    val accessFlag: Int = AccessFlag.getJawaFlags(access, FlagKind.METHOD, if(name == "<init>" || name == "<clinit>") true else false)
    val signature: Signature = JavaKnowledge.genSignature(JavaKnowledge.formatTypeToSignature(cityp.typ), name, desc)
    new MethodDeclResolver(api, accessFlag, signature, methods)
  }
}
