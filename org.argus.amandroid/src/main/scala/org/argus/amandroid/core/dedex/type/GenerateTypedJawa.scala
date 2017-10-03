/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex.`type`

import java.util

import org.argus.amandroid.core.dedex.`type`.LocalTypeResolver.VarType
import org.argus.amandroid.core.dedex.{JawaModelProvider, JawaStyleCodeGenerator}
import org.argus.jawa.alir.reachingDefinitionAnalysis.VarSlot
import org.argus.jawa.ast._

import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.io.Position
import org.argus.jawa.core.util._
import org.argus.jawa.core.{AccessFlag, Global, JavaKnowledge, JawaType}
import org.stringtemplate.v4.{ST, STGroupString}

import collection.JavaConverters._

/**
  * Created by fgwei on 4/28/17.
  */
object GenerateTypedJawa {

  def apply(code: String, global: Global): String = {
    val sb: StringBuilder = new StringBuilder
    JawaParser.parse[CompilationUnit](Left(code), resolveBody = true, global.reporter, classOf[CompilationUnit]) match {
      case Left(cu) =>
        if(!cu.localTypResolved) {
          cu.topDecls foreach { clazz =>
            sb.append(generateRecord(global, clazz))
          }
        }
      case Right(e) => global.reporter.error(e.pos, e.message)
    }
    sb.toString()
  }

  private def generateRecord(global: Global, clazz: ClassOrInterfaceDeclaration): String = {
    val template = new STGroupString(JawaModelProvider.jawaModel)
    val recTemplate = template.getInstanceOf("RecordDecl")
    recTemplate.add("recName", clazz.typ.jawaName)
    val recAnnotations = new util.ArrayList[ST]
    recAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("kind", if(clazz.isInterface) "interface" else "class", template))
    recAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("AccessFlag", clazz.accessModifier, template))
    recTemplate.add("annotations", recAnnotations)

    val extendsList: util.ArrayList[ST] = new util.ArrayList[ST]
    clazz.superClassOpt foreach { sc =>
      val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
      extOrImpTemplate.add("recName", sc.jawaName)
      val extAnnotations = new util.ArrayList[ST]
      extAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("kind", "class", template))
      extOrImpTemplate.add("annotations", extAnnotations)
      extendsList.add(extOrImpTemplate)
    }
    clazz.interfaces foreach { ic =>
      val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
      extOrImpTemplate.add("recName", ic.jawaName)
      val impAnnotations = new util.ArrayList[ST]
      impAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("kind", "interface", template))
      extOrImpTemplate.add("annotations", impAnnotations)
      extendsList.add(extOrImpTemplate)
    }
    recTemplate.add("extends", extendsList)
    recTemplate.add("attributes", clazz.instanceFieldDeclarationBlock.instanceFields.map(_.toCode).asJava)
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
    var newvar = typ.baseTyp.substring(typ.baseTyp.lastIndexOf(".") + 1) + {if(typ.dimensions > 0)"_arr" + typ.dimensions else ""} + "_" + v
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
    procTemplate.add("retTyp", JawaStyleCodeGenerator.generateType(signature.getReturnType, template))
    procTemplate.add("procedureName", method.methodSymbol.id.text)
    val params: util.ArrayList[ST] = new util.ArrayList[ST]
    method.thisParam foreach { thisP =>
      val thisType = thisP.typ.typ
      val paramTemplate = template.getInstanceOf("Param")
      paramTemplate.add("paramTyp", JawaStyleCodeGenerator.generateType(thisType, template))
      paramTemplate.add("paramName", genVarName(thisP.name, thisType, Some("this"), isParam = true, localvars, realnameMap))
      val thisAnnotations = new util.ArrayList[ST]
      thisAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("kind", "this", template))
      paramTemplate.add("annotations", thisAnnotations)
      params.add(paramTemplate)
    }
    method.paramList foreach { p =>
      val paramType = p.typ.typ
      val paramName = p.annotations.find(a => a.key == "name").map(_.value).filter(_.nonEmpty)

      val paramTemplate = template.getInstanceOf("Param")
      paramTemplate.add("paramTyp", JawaStyleCodeGenerator.generateType(paramType, template))
      paramTemplate.add("paramName", genVarName(p.name, paramType, paramName, isParam = true, localvars, realnameMap))
      val paramAnnotations = new util.ArrayList[ST]
      if(!JavaKnowledge.isJavaPrimitive(paramType)) {
        paramAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("kind", "object", template))
      }
      paramTemplate.add("annotations", paramAnnotations)
      params.add(paramTemplate)
    }
    procTemplate.add("params", params)
    val procAnnotations = new util.ArrayList[ST]
    procAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("owner", "^" + JawaStyleCodeGenerator.generateType(signature.getClassType, template).render(), template))
    procAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("signature", "`" + signature.signature + "`", template))
    procAnnotations.add(JawaStyleCodeGenerator.generateAnnotation("AccessFlag", method.accessModifier, template))
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
          val regName = JawaStyleCodeGenerator.generateType(typ, template).render() + " " + name + ";"
          locals.add(regName)
        }
    }
    localVarsTemplate.add("locals", locals)
    localVarsTemplate
  }

  private def updateCode(loccode: String, pos: Position, newtext: String): String = {
    val sb: StringBuffer = new StringBuffer
    sb.append(loccode)
    val start = pos.column
    val end = pos.column + pos.end - pos.start + 1
    sb.replace(start, end, newtext)
    sb.toString.intern()
  }

  private def resolveVar(global: Global, code: String, varSymbol: VarSymbol, types: IMap[VarSlot, VarType], localvars: MMap[String, (JawaType, Boolean)], realnameMap: MMap[String, String]): String = {
    val pos = varSymbol.id.pos
    val slot = VarSlot(varSymbol.varName)
    val typ: JawaType = types.get(slot) match {
      case Some(t) => t.getJawaType(global)
      case None => throw new LocalTypeResolveException(pos, "Type should be resolved.")
    }
    val varName = genVarName(varSymbol.varName, typ, None, isParam = false, localvars, realnameMap)
    updateCode(code, pos, varName)
  }

  private def generateBody(global: Global, method: MethodDeclaration, localvars: MMap[String, (JawaType, Boolean)], realnameMap: MMap[String, String], def_types: IMap[Int, IMap[VarSlot, VarType]], use_types: IMap[Int, IMap[VarSlot, VarType]], template: STGroupString): ST = {
    val bodyTemplate: ST = template.getInstanceOf("Body")

    val codes: util.ArrayList[String] = new util.ArrayList[String]
    method.resolvedBody.locations.foreach { location =>
      var code = location.toCode
      val defs: IMap[VarSlot, VarType] = def_types.getOrElse(location.locationIndex, imapEmpty)
      val uses: IMap[VarSlot, VarType] = use_types.getOrElse(location.locationIndex, imapEmpty)
      var nullable: Option[Position] = None
      location.statement match {
        case a: Assignment =>
          a.getRhs match {
            case ae: AccessExpression =>
              code = resolveVar(global, code, ae.varSymbol, uses, localvars, realnameMap)
            case be: BinaryExpression =>
              be.right match {
                case Left(v) =>
                  code = resolveVar(global, code, v, uses, localvars, realnameMap)
                case Right(_) =>
              }
              code = resolveVar(global, code, be.left, uses, localvars, realnameMap)
            case cr: CallRhs =>
              cr.argClause.varSymbols.reverse.foreach {
                case (v, _) =>
                  code = resolveVar(global, code, v, uses, localvars, realnameMap)
              }
            case ce: CastExpression =>
              code = resolveVar(global, code, ce.varSym, uses, localvars, realnameMap)
            case ce: CmpExpression =>
              code = resolveVar(global, code, ce.var2Symbol, uses, localvars, realnameMap)
              code = resolveVar(global, code, ce.var1Symbol, uses, localvars, realnameMap)
            case _: ConstClassExpression =>
            case _: ExceptionExpression =>
            case ie: IndexingExpression =>
              ie.indices.reverse.foreach { i =>
                i.index match {
                  case Left(v) =>
                    code = resolveVar(global, code, v, uses, localvars, realnameMap)
                  case Right(_) =>
                }
              }
              code = resolveVar(global, code, ie.varSymbol, uses, localvars, realnameMap)
            case ie: InstanceofExpression =>
              code = resolveVar(global, code, ie.varSymbol, uses, localvars, realnameMap)
            case le: LengthExpression =>
              code = resolveVar(global, code, le.varSymbol, uses, localvars, realnameMap)
            case le: LiteralExpression =>
              if(le.isInt && le.getInt == 0) {
                nullable = Some(le.pos)
              }
            case ne: NameExpression =>
              ne.varSymbol match {
                case Left(v) =>
                  code = resolveVar(global, code, v, uses, localvars, realnameMap)
                case Right(_) =>
              }
            case ne: NewExpression =>
              ne.typeFragmentsWithInit.reverse.foreach { init =>
                init.varSymbols.reverse.foreach { case (v, _) =>
                  code = resolveVar(global, code, v, uses, localvars, realnameMap)
                }
              }
            case _: NullExpression =>
            case _: TupleExpression =>
            case ue: UnaryExpression =>
              code = resolveVar(global, code, ue.unary, uses, localvars, realnameMap)
          }
          a.getLhs foreach {
            case ae: AccessExpression =>
              code = resolveVar(global, code, ae.varSymbol, uses, localvars, realnameMap)
            case cl: CallLhs =>
              code = resolveVar(global, code, cl.lhs, defs, localvars, realnameMap)
            case ie: IndexingExpression =>
              ie.indices.reverse.foreach { i =>
                i.index match {
                  case Left(v) =>
                    code = resolveVar(global, code, v, uses, localvars, realnameMap)
                  case Right(_) =>
                }
              }
              code = resolveVar(global, code, ie.varSymbol, uses, localvars, realnameMap)
            case ne: NameExpression =>
              ne.varSymbol match {
                case Left(v) =>
                  nullable match {
                    case Some(pos) =>
                      val typ: JawaType = defs.get(VarSlot(v.varName)) match {
                        case Some(t) => t.getJawaType(global)
                        case None => throw new LocalTypeResolveException(pos, "Type should be resolved.")
                      }
                      if(typ.isObject) code = updateCode(code, pos, "null")
                    case None =>
                  }
                  code = resolveVar(global, code, v, defs, localvars, realnameMap)
                case Right(_) =>
              }
          }
        case _: EmptyStatement =>
        case ms: MonitorStatement =>
          code = resolveVar(global, code, ms.varSymbol, uses, localvars, realnameMap)
        case _: GotoStatement =>
        case is: IfStatement =>
          is.cond.right match {
            case Left(v) =>
              code = resolveVar(global, code, v, uses, localvars, realnameMap)
            case Right(l) =>
              l match {
                case Left(i) =>
                  val typ: JawaType = uses.get(VarSlot(is.cond.left.varName)) match {
                    case Some(t) => t.getJawaType(global)
                    case None => throw new LocalTypeResolveException(is.cond.left.pos, "Type should be resolved.")
                  }
                  if(typ.isObject) {
                    code = updateCode(code, i.pos, "null")
                  }
                case Right(_) =>
              }
          }
          code = resolveVar(global, code, is.cond.left, uses, localvars, realnameMap)
        case rs: ReturnStatement =>
          rs.varOpt match {
            case Some(v) =>
              code = resolveVar(global, code, v, uses, localvars, realnameMap)
            case None =>
          }
        case ss: SwitchStatement =>
          code = resolveVar(global, code, ss.condition, uses, localvars, realnameMap)
        case ts: ThrowStatement =>
          code = resolveVar(global, code, ts.varSymbol, uses, localvars, realnameMap)
      }
      codes.add(code)
    }
    bodyTemplate.add("codeFragments", codes)
    bodyTemplate
  }

}
