/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.java

import java.util

import com.github.javaparser.ast._
import com.github.javaparser.ast.`type`._
import com.github.javaparser.ast.body._
import com.github.javaparser.ast.expr.{AnnotationExpr, NormalAnnotationExpr, SingleMemberAnnotationExpr}
import org.argus.jawa.ast.{AnnotationValue, ExtendAndImplement, ExtendsAndImplementsClauses, FieldDefSymbol, InstanceFieldDeclaration, InstanceFieldDeclarationBlock, StatementValue, StaticFieldDeclaration, TokenValue, TypeDefSymbol, TypeFragment, TypeSymbol, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit, Type => JawaTypeAst}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.io.{JavaSourceFile, RangePosition}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JavaKnowledge, JawaType}

class Java2Jawa(global: Global, sourceFile: JavaSourceFile) {

  private var packageName: String = ""

  private val imports: NodeList[ImportDeclaration] = sourceFile.getJavaCU.getImports

  private val typeMap: MMap[String, JawaType] = mmapEmpty

  private def findType(cit: ClassOrInterfaceType): JawaType = {
    typeMap.get(cit.asString()) match {
      case Some(t) => t
      case None =>
        var typOpt: Option[JawaType] = None
        imports.forEach { imp =>
          if(!imp.isStatic && !imp.isAsterisk) {
            val typ = new JawaType(imp.getNameAsString)
            if(typ.jawaName.endsWith(cit.asString())) {
              typOpt = Some(typ)
            }
          } else if(!imp.isStatic && imp.isAsterisk) {
            val typ = new JawaType(s"${imp.getNameAsString}.${cit.asString()}")
            global.getClazz(typ) match {
              case Some(_) => typOpt = Some(typ)
              case None =>
            }
          }
        }
        typOpt match {
          case None =>
            // java.lang.* is implicit applied
            val typ = new JawaType(s"java.lang.${cit.asString()}")
            global.getClazz(typ) match {
              case Some(_) => typOpt = Some(typ)
              case None =>
            }
          case _ =>
        }
        typOpt match {
          case Some(typ) => typ
          case None =>
            global.reporter.error(cit.getName.toRange.pos, s"Could not resolve type: ${cit.asString()}")
            new JawaType(cit.asString())
        }
    }
  }

  private def findType(javaType: Type): JawaType = {
    var typStr: String = null
    var dimension: Int = 0
    javaType match {
      case at: ArrayType =>
        typStr = findType(at.getElementType).jawaName
        dimension = at.getArrayLevel
      case cit: ClassOrInterfaceType =>
        typStr = findType(cit).jawaName
      case it: IntersectionType =>
        val jawaTypes: MList[JawaType] = mlistEmpty
        it.getElements.forEach{ elem =>
          jawaTypes += findType(elem)
        }
        typStr = jawaTypes.map(t => t.jawaName).mkString("&")
      case pt: PrimitiveType =>
        pt.getType match {
          case PrimitiveType.Primitive.BOOLEAN => typStr = "boolean"
          case PrimitiveType.Primitive.BYTE => typStr = "byte"
          case PrimitiveType.Primitive.CHAR => typStr = "char"
          case PrimitiveType.Primitive.DOUBLE => typStr = "double"
          case PrimitiveType.Primitive.FLOAT => typStr = "float"
          case PrimitiveType.Primitive.INT => typStr = "int"
          case PrimitiveType.Primitive.LONG => typStr = "long"
          case PrimitiveType.Primitive.SHORT => typStr = "short"
          case _ =>
            global.reporter.error(javaType.toRange.pos, s"Unknown primitive type: $pt")
            typStr = "int"
        }
      case _: VoidType =>
        typStr = "void"
      case _ =>
        throw Java2JawaException(s"${javaType.getClass} is not handled by jawa: $javaType")
    }
    new JawaType(typStr, dimension)
  }

  implicit class TransRange(node: Node) {
    def toRange: RangePosition = {
      val nodeRange = node.getRange
      if(nodeRange.isPresent) {
        val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line) + nodeRange.get().begin.column
        val endIn = sourceFile.lineToOffset(nodeRange.get().end.line) + nodeRange.get().end.column
        new RangePosition(sourceFile, startIn, endIn - startIn + 1, nodeRange.get().begin.line, nodeRange.get().begin.column)
      } else {
        new RangePosition(sourceFile, 0, 0, 0, 0)
      }
    }
  }

  private def getKeyWordRange(node: Node): RangePosition = {
    val nodeRange = node.getRange
    if(nodeRange.isPresent) {
      val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line) + nodeRange.get().begin.column
      new RangePosition(sourceFile, startIn, startIn + 1)
    } else {
      new RangePosition(sourceFile, 0, 0, 0, 0)
    }
  }

  implicit class StringProcess(str: String) {
    def apostrophe: String = "`%s`".format(str)
  }

  private def getJawaAccessFlag(modifiers: util.EnumSet[Modifier]): String = {
    val flags: MList[String] = mlistEmpty
    modifiers.forEach {
      case Modifier.PUBLIC => flags += "PUBLIC"
      case Modifier.PROTECTED => flags += "PROTECTED"
      case Modifier.PRIVATE => flags += "PRIVATE"
      case Modifier.ABSTRACT => flags += "ABSTRACT"
      case Modifier.STATIC => flags += "STATIC"
      case Modifier.FINAL => flags += "FINAL"
      case Modifier.TRANSIENT => flags += "TRANSIENT"
      case Modifier.VOLATILE => flags += "VOLATILE"
      case Modifier.SYNCHRONIZED => flags += "SYNCHRONIZED"
      case Modifier.NATIVE => flags += "NATIVE"
      case Modifier.STRICTFP => flags += "STRICTFP"
      case Modifier.TRANSITIVE => flags += "TRANSITIVE"
      case Modifier.DEFAULT => flags += "DEFAULT"
    }
    flags.mkString("_")
  }

  private def handleType(javaType: Type): JawaTypeAst = {
    val jawaType = findType(javaType)
    val baseTypeSymbol: Either[TypeSymbol, Token] = {
      jawaType.baseTyp match {
        case x if JavaKnowledge.isJavaPrimitive(x) => Right(Token(Tokens.ID, javaType.getElementType.toRange, x.apostrophe))
        case t => Left(TypeSymbol(Token(Tokens.ID, javaType.getElementType.toRange, t)))
      }
    }
    val typeFragments: IList[TypeFragment] = (0 until jawaType.dimensions).map { _ =>
      TypeFragment(getKeyWordRange(javaType))
    }.toList
    JawaTypeAst(baseTypeSymbol, typeFragments)
  }

  def process: JawaCompilationUnit = {
    process(sourceFile.getJavaCU)
  }

  def process(cu: CompilationUnit): JawaCompilationUnit = {
    cu.getImports
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    cu.getTypes.forEach(typ => process(typ))
    null
  }

  def process(typ: TypeDeclaration[_]): JawaClassOrInterfaceDeclaration = {
    typ match {
      case cid: ClassOrInterfaceDeclaration =>
        val cityp: TypeDefSymbol = TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"$packageName.${cid.getNameAsString}".apostrophe))
        val annotations: MList[JawaAnnotation] = mlistEmpty

        // add kind annotation
        val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
        val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), {if(cid.isInterface) "interface" else "class"}))
        annotations += JawaAnnotation(kindKey, Some(kindValue))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(cid), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), getJawaAccessFlag(cid.getModifiers)))
        annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))
        // add java annotations
        cid.getAnnotations.forEach{ anno =>
          annotations += process(anno)
        }

        // Resolve extends
        var extendAndImplNum = cid.getExtendedTypes.size() + cid.getImplementedTypes.size()
        val extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses] = if(extendAndImplNum > 0) {
          val parentTyps: MList[ExtendAndImplement] = mlistEmpty
          cid.getExtendedTypes.forEach{ et =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "class"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, findType(et).jawaName)), List(annotation))
            parentTyps += ei
          }
          cid.getImplementedTypes.forEach{ et =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "interface"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, findType(et).jawaName)), List(annotation))
            parentTyps += ei
          }
          Some(ExtendsAndImplementsClauses(parentTyps.toList))
        } else {
          None
        }

        // Resolve fields
        val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
        val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
        cid.getFields.forEach { f =>
          f.getVariables.forEach{ va =>
            val jawaTypeAst = handleType(va.getType)
            val fieldSymbol = FieldDefSymbol(Token(Tokens.ID, va.getName.toRange, s"${cityp.typ.jawaName}.${va.getNameAsString}"))
            // add access flag annotation
            val accessFlagKey = Token(Tokens.ID, getKeyWordRange(f), "AccessFlag")
            val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(f), getJawaAccessFlag(f.getModifiers)))
            val accessFlagAnnotation = JawaAnnotation(accessFlagKey, Some(accessFlagValue))
            if(f.isStatic) {
              staticFields += StaticFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))
            } else {
              instanceFields += InstanceFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))
            }
          }
        }
        val instanceFieldDeclarationBlock: InstanceFieldDeclarationBlock = InstanceFieldDeclarationBlock(instanceFields.toList)
//        methods: IList[MethodDeclaration]
        JawaClassOrInterfaceDeclaration(cityp, annotations.toList, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields.toList, null)
      case _: EnumDeclaration =>
        null // TODO
      case _: AnnotationDeclaration =>
        null // TODO
    }
  }

  def process(ae: AnnotationExpr): JawaAnnotation = {
    val annoKey = Token(Tokens.ID, ae.getName.toRange, ae.getNameAsString)
    val annoValue: Option[AnnotationValue] = ae match {
      case _: NormalAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _: SingleMemberAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _ => None // MarkerAnnotationExpr
    }
    JawaAnnotation(annoKey, annoValue)
  }
}

case class Java2JawaException(msg: String) extends RuntimeException