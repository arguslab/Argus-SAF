/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex.`type`

import java.util

import org.argus.amandroid.core.dedex.`type`.LocalTypeResolver.VarType
import org.argus.jawa.flow.rda.VarSlot
import org.argus.jawa.core.ast._
import org.argus.jawa.core.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.compiler.parser._
import org.argus.jawa.core.codegen.JawaModelProvider
import org.argus.jawa.core.elements.{AccessFlag, JawaType}
import org.argus.jawa.core.io.{NoPosition, Position}
import org.argus.jawa.core.util._
import org.argus.jawa.core.Global
import org.stringtemplate.v4.{ST, STGroupString}

import scala.collection.JavaConverters._
import scala.util.{Failure, Success}

/**
  * Created by fgwei on 4/28/17.
  */
object GenerateTypedJawa {

  def apply(code: String, global: Global): String = {
    val sb: StringBuilder = new StringBuilder
    JawaParser.parse[CompilationUnit](Left(code), resolveBody = true, global.reporter, classOf[CompilationUnit]) match {
      case Success(cu) =>
        if(!cu.localTypResolved) {
          cu.topDecls foreach { clazz =>
            sb.append(generateRecord(global, clazz))
          }
        }
      case Failure(e) => global.reporter.error(NoPosition, e.getMessage)
    }
    sb.toString()
  }

  private def generateRecord(global: Global, clazz: ClassOrInterfaceDeclaration): String = {
    val template = new STGroupString(JawaModelProvider.jawaModel)
    val recTemplate = template.getInstanceOf("RecordDecl")
    recTemplate.add("recName", clazz.typ.jawaName)
    val recAnnotations = new util.ArrayList[ST]
    recAnnotations.add(JawaModelProvider.generateAnnotation("kind", if(clazz.isInterface) "interface" else "class", template))
    recAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", clazz.accessModifier, template))
    recTemplate.add("annotations", recAnnotations)

    val extendsList: util.ArrayList[ST] = new util.ArrayList[ST]
    clazz.superClassOpt foreach { sc =>
      val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
      extOrImpTemplate.add("recName", sc.jawaName)
      val extAnnotations = new util.ArrayList[ST]
      extAnnotations.add(JawaModelProvider.generateAnnotation("kind", "class", template))
      extOrImpTemplate.add("annotations", extAnnotations)
      extendsList.add(extOrImpTemplate)
    }
    clazz.interfaces foreach { ic =>
      val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
      extOrImpTemplate.add("recName", ic.jawaName)
      val impAnnotations = new util.ArrayList[ST]
      impAnnotations.add(JawaModelProvider.generateAnnotation("kind", "interface", template))
      extOrImpTemplate.add("annotations", impAnnotations)
      extendsList.add(extOrImpTemplate)
    }
    recTemplate.add("extends", extendsList)
    recTemplate.add("attributes", clazz.instanceFields.map(_.toCode).asJava)
    recTemplate.add("globals", clazz.staticFields.map(_.toCode).asJava)
    recTemplate.add("procedures", generateProcedures(global, clazz, template))
    recTemplate.render()
  }

  private def generateProcedures(global: Global, clazz: ClassOrInterfaceDeclaration, template: STGroupString): util.ArrayList[ST] = {
    val procedures: util.ArrayList[ST] = new util.ArrayList[ST]
    clazz.methods foreach { method =>
      procedures.add(generateProcedure(global, method, template))
    }
    procedures
  }

  private def genVarName(v: String, typ: JawaType, nameOpt: Option[String], isParam: Boolean, localvars: MMap[String, (JawaType, Boolean)], realnameMap: MMap[String, String]): String = {
    var newvar = typ.baseType.name + {if(typ.dimensions > 0)"_arr" + typ.dimensions else ""} + "_" + v
    while(localvars.contains(newvar) && localvars(newvar)._1 != typ) newvar = "a_" + newvar
    if(!localvars.contains(newvar)) localvars(newvar) = (typ, isParam)
    nameOpt match {
      case Some(name) => realnameMap(newvar) = s"`$name`"
      case None =>
    }
    realnameMap.get(newvar) match {
      case Some(real) => real
      case None => newvar
    }
  }

  private def generateProcedure(global: Global, method: MethodDeclaration, template: STGroupString): ST = {
    val (def_types, use_types) = LocalTypeResolver(global, method)

    val localvars: MMap[String, (JawaType, Boolean)] = mmapEmpty
    val realnameMap: MMap[String, String] = mmapEmpty

    val signature = method.signature
    val procTemplate = template.getInstanceOf("ProcedureDecl")
    procTemplate.add("retTyp", JawaModelProvider.generateType(signature.getReturnType, template))
    procTemplate.add("procedureName", method.methodSymbol.id.text)
    val params: util.ArrayList[ST] = new util.ArrayList[ST]
    method.thisParam foreach { thisP =>
      val thisType = thisP.typ.typ
      val paramTemplate = template.getInstanceOf("Param")
      paramTemplate.add("paramTyp", JawaModelProvider.generateType(thisType, template))
      paramTemplate.add("paramName", genVarName(thisP.name, thisType, Some("this"), isParam = true, localvars, realnameMap))
      val thisAnnotations = new util.ArrayList[ST]
      thisAnnotations.add(JawaModelProvider.generateAnnotation("kind", "this", template))
      paramTemplate.add("annotations", thisAnnotations)
      params.add(paramTemplate)
    }
    method.paramList foreach { p =>
      val paramType = p.typ.typ
      val paramName = p.annotations.find(a => a.key == "name").map(_.value).filter(_.nonEmpty)

      val paramTemplate = template.getInstanceOf("Param")
      paramTemplate.add("paramTyp", JawaModelProvider.generateType(paramType, template))
      paramTemplate.add("paramName", genVarName(p.name, paramType, paramName, isParam = true, localvars, realnameMap))
      val paramAnnotations = new util.ArrayList[ST]
      if(paramType.isObject) {
        paramAnnotations.add(JawaModelProvider.generateAnnotation("kind", "object", template))
      }
      paramTemplate.add("annotations", paramAnnotations)
      params.add(paramTemplate)
    }
    procTemplate.add("params", params)
    val procAnnotations = new util.ArrayList[ST]
    procAnnotations.add(JawaModelProvider.generateAnnotation("signature", "`" + signature.signature + "`", template))
    procAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", method.accessModifier, template))
    procTemplate.add("annotations", procAnnotations)
    if(!AccessFlag.isAbstract(AccessFlag.getAccessFlags(method.accessModifier)) &&
      !AccessFlag.isNative(AccessFlag.getAccessFlags(method.accessModifier))) {
      val body = generateBody(global, method, localvars, realnameMap, def_types, use_types, template)
      procTemplate.add("localVars", generateLocalVars(localvars.toMap, template))
      procTemplate.add("body", body)
      val catchesTemplate: ST = template.getInstanceOf("CatchClauses")
      val catches = new util.ArrayList[String]
      catches.addAll(method.resolvedBody.catchClauses.map(_.toCode).asJava)
      catchesTemplate.add("catches", catches)
      procTemplate.add("catchClauses", catchesTemplate)
    } else {
      procTemplate.add("body", "# return;")
    }
    procTemplate
  }

  private def generateLocalVars(localvars: IMap[String, (JawaType, Boolean)], template: STGroupString): ST = {
    val localVarsTemplate: ST = template.getInstanceOf("LocalVars")
    val locals: util.ArrayList[String] = new util.ArrayList[String]
    localvars.foreach {
      case (name, (typ, param)) =>
        if(!param) {
          val regName = JawaModelProvider.generateType(typ, template).render() + " " + name + ";"
          locals.add(regName)
        }
    }
    localVarsTemplate.add("locals", locals)
    localVarsTemplate
  }

  private def resolveVar(global: Global, varSymbol: VarSymbol, types: IMap[VarSlot, VarType], localvars: MMap[String, (JawaType, Boolean)], realnameMap: MMap[String, String]): VarSymbol = {
    val pos = varSymbol.id.pos
    val slot = VarSlot(varSymbol.varName)
    val typ: JawaType = types.get(slot) match {
      case Some(t) => t.getJawaType(global)
      case None => throw new LocalTypeResolveException(pos, "Type should be resolved.")
    }
    val varName = genVarName(varSymbol.varName, typ, None, isParam = false, localvars, realnameMap)
    VarSymbol(Token(varSymbol.id.tokenType, varSymbol.id.pos, varName))(varSymbol.pos)
  }

  private def generateBody(global: Global, method: MethodDeclaration, localvars: MMap[String, (JawaType, Boolean)], realnameMap: MMap[String, String], def_types: IMap[Int, IMap[VarSlot, VarType]], use_types: IMap[Int, IMap[VarSlot, VarType]], template: STGroupString): ST = {
    val bodyTemplate: ST = template.getInstanceOf("Body")

    val codes: util.ArrayList[String] = new util.ArrayList[String]
    method.resolvedBody.locations.foreach { location =>
      val defs: IMap[VarSlot, VarType] = def_types.getOrElse(location.locationIndex, imapEmpty)
      val uses: IMap[VarSlot, VarType] = use_types.getOrElse(location.locationIndex, imapEmpty)
      var nullable: Option[Position] = None
      val newStatement: Statement = location.statement match {
        case a: AssignmentStatement =>
          var lhs = a.lhs
          var rhs = a.rhs
          a.getRhs match {
            case ae: AccessExpression =>
              val vs = resolveVar(global, ae.varSymbol, uses, localvars, realnameMap)
              rhs = AccessExpression(vs, ae.fieldSym, ae.typExp)(ae.pos)
            case be: BinaryExpression =>
              val left = resolveVar(global, be.left, uses, localvars, realnameMap)
              val right: Either[VarSymbol, Either[LiteralExpression, NullExpression]] = be.right match {
                case Left(v) =>
                  val vs = resolveVar(global, v, uses, localvars, realnameMap)
                  Left(vs)
                case r @ Right(_) =>
                  r
              }
              rhs = BinaryExpression(left, be.op, right)(be.pos)
            case ce: CastExpression =>
              val vs = resolveVar(global, ce.varSym, uses, localvars, realnameMap)
              rhs = CastExpression(ce.typ, vs)(ce.pos)
            case ce: CmpExpression =>
              val var2Symbol = resolveVar(global, ce.var2Symbol, uses, localvars, realnameMap)
              val var1Symbol = resolveVar(global, ce.var1Symbol, uses, localvars, realnameMap)
              rhs = CmpExpression(ce.cmp, var1Symbol, var2Symbol)(ce.pos)
            case _: ConstClassExpression =>
            case _: ExceptionExpression =>
            case ie: IndexingExpression =>
              val indices = ie.indices.map { i =>
                val index: Either[VarSymbol, LiteralExpression] = i.index match {
                  case Left(v) =>
                    val vs = resolveVar(global, v, uses, localvars, realnameMap)
                    Left(vs)
                  case r @ Right(_) =>
                    r
                }
                IndexingSuffix(index)(i.pos)
              }
              val vs = resolveVar(global, ie.varSymbol, uses, localvars, realnameMap)
              rhs = IndexingExpression(vs, indices)(ie.pos)
            case ie: InstanceOfExpression =>
              val vs = resolveVar(global, ie.varSymbol, uses, localvars, realnameMap)
              rhs = InstanceOfExpression(vs, ie.typExp)(ie.pos)
            case le: LengthExpression =>
              val vs = resolveVar(global, le.varSymbol, uses, localvars, realnameMap)
              rhs = LengthExpression(vs)(le.pos)
            case le: LiteralExpression =>
              if(le.isInt && le.getInt == 0) {
                nullable = Some(le.pos)
              }
            case ne: VariableNameExpression =>
              val vs = resolveVar(global, ne.varSymbol, uses, localvars, realnameMap)
              rhs = VariableNameExpression(vs)(ne.pos)
            case _: StaticFieldAccessExpression =>
            case _: NewExpression =>
            case nae: NewArrayExpression =>
              val vss = nae.varSymbols.map { vs =>
                resolveVar(global, vs, uses, localvars, realnameMap)
              }
              rhs = NewArrayExpression(nae.base, vss)(nae.pos)
            case _: NullExpression =>
            case _: TupleExpression =>
            case ue: UnaryExpression =>
              val vs = resolveVar(global, ue.unary, uses, localvars, realnameMap)
              rhs = UnaryExpression(ue.op, vs)(ue.pos)
            case _ =>
          }
          a.getLhs foreach {
            case ae: AccessExpression =>
              val vs = resolveVar(global, ae.varSymbol, uses, localvars, realnameMap)
              lhs = AccessExpression(vs, ae.fieldSym, ae.typExp)(ae.pos)
            case ie: IndexingExpression =>
              val indices: IList[IndexingSuffix] = ie.indices.map { i =>
                val index: Either[VarSymbol, LiteralExpression] = i.index match {
                  case Left(v) =>
                    val vs = resolveVar(global, v, uses, localvars, realnameMap)
                    Left(vs)
                  case r @ Right(_) =>
                    r
                }
                IndexingSuffix(index)(i.pos)
              }
              val vs = resolveVar(global, ie.varSymbol, uses, localvars, realnameMap)
              lhs = IndexingExpression(vs, indices)(ie.pos)
            case ne: VariableNameExpression =>
              nullable match {
                case Some(pos) =>
                  val typ: JawaType = defs.get(VarSlot(ne.varSymbol.varName)) match {
                    case Some(t) => t.getJawaType(global)
                    case None => throw new LocalTypeResolveException(pos, "Type should be resolved.")
                  }
                  if(typ.isObject) {
                    rhs = NullExpression(Token(Tokens.NULL, pos, "null"))(pos)
                  }
                case None =>
              }
              val vs = resolveVar(global, ne.varSymbol, defs, localvars, realnameMap)
              lhs = VariableNameExpression(vs)(ne.pos)
            case _: StaticFieldAccessExpression =>
            case _ =>
          }
          AssignmentStatement(lhs, rhs, a.annotations)(a.pos)
        case cs: CallStatement =>
          val varSymbols = cs.rhs.varSymbols.map { v =>
            resolveVar(global, v, uses, localvars, realnameMap)
          }
          val rhs = CallRhs(cs.rhs.methodNameSymbol, varSymbols)(cs.rhs.pos)
          val lhsOpt = cs.lhsOpt match {
            case Some(lhs) =>
              val vs = resolveVar(global, lhs.varSymbol, defs, localvars, realnameMap)
              Some(VariableNameExpression(vs)(lhs.pos))
            case None =>
              None
          }
          CallStatement(lhsOpt, rhs, cs.annotations)(cs.pos)
        case e: EmptyStatement =>
          e
        case ms: MonitorStatement =>
          val vs = resolveVar(global, ms.varSymbol, uses, localvars, realnameMap)
          MonitorStatement(ms.monitor, vs)(ms.pos)
        case g: GotoStatement =>
          g
        case is: IfStatement =>
          val right: Either[VarSymbol, Either[LiteralExpression, NullExpression]] = is.cond.right match {
            case Left(v) =>
              val vs = resolveVar(global, v, uses, localvars, realnameMap)
              Left(vs)
            case Right(l) =>
              val ln: Either[LiteralExpression, NullExpression] = l match {
                case Left(i) =>
                  val typ: JawaType = uses.get(VarSlot(is.cond.left.varName)) match {
                    case Some(t) => t.getJawaType(global)
                    case None => throw new LocalTypeResolveException(is.cond.left.pos, "Type should be resolved.")
                  }
                  if(typ.isObject) {
                    Right(NullExpression(Token(Tokens.NULL, i.pos, "null"))(i.pos))
                  } else {
                    Left(i)
                  }
                case r @ Right(_) =>
                  r
              }
              Right(ln)
          }
          val left = resolveVar(global, is.cond.left, uses, localvars, realnameMap)
          val be = BinaryExpression(left, is.cond.op, right)(is.cond.pos)
          IfStatement(be, is.targetLocation)(is.pos)
        case rs: ReturnStatement =>
          val varOpt = rs.varOpt match {
            case Some(v) =>
              val vs = resolveVar(global, v, uses, localvars, realnameMap)
              Some(vs)
            case None =>
              None
          }
          ReturnStatement(varOpt, rs.annotations)(rs.pos)
        case ss: SwitchStatement =>
          val vs = resolveVar(global, ss.condition, uses, localvars, realnameMap)
          SwitchStatement(vs, ss.cases, ss.defaultCaseOpt)(ss.pos)
        case ts: ThrowStatement =>
          val vs = resolveVar(global, ts.varSymbol, uses, localvars, realnameMap)
          ThrowStatement(vs)(ts.pos)
        case a =>
          a
      }
      val newLoc = Location(location.locationSymbol, newStatement)(location.pos)
      codes.add(newLoc.toCode)
    }
    bodyTemplate.add("codeFragments", codes)
    bodyTemplate
  }

}
