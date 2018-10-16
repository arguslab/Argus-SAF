/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.elements

import org.argus.jawa.core.java_signatures.JavaType.BaseType
import org.argus.jawa.core.java_signatures.{ClassType, JavaType, PrimitiveType}
import org.argus.jawa.core.util._

object JawaType {
  def generateType(typ: String, dimensions: Int): JawaType = {
    new JawaType(typ, dimensions)
  }
  
  def addDimensions(typ: JawaType, dimensions: Int): JawaType = {
    if(typ.dimensions + dimensions >= 0) {
      new JawaType(typ.baseType, typ.dimensions + dimensions)
    } else typ
  }
}

final case class JawaBaseType(base_type: Either[PrimitiveType, ClassType]) {
  def this(pkg: Option[JawaPackage], name: String, unknown: Boolean = false) =
    this(pkg match {
      case Some(p) => Right(ClassType(`package` = Some(p.pkg), name = name, unknown = unknown))
      case None =>
        name match {
          case "byte" =>    Left(PrimitiveType(`type` = PrimitiveType.Primitive.BYTE))
          case "char" =>    Left(PrimitiveType(`type` = PrimitiveType.Primitive.CHAR))
          case "double" =>  Left(PrimitiveType(`type` = PrimitiveType.Primitive.DOUBLE))
          case "float" =>   Left(PrimitiveType(`type` = PrimitiveType.Primitive.FLOAT))
          case "int" =>     Left(PrimitiveType(`type` = PrimitiveType.Primitive.INT))
          case "long" =>    Left(PrimitiveType(`type` = PrimitiveType.Primitive.LONG))
          case "short" =>   Left(PrimitiveType(`type` = PrimitiveType.Primitive.SHORT))
          case "boolean" => Left(PrimitiveType(`type` = PrimitiveType.Primitive.BOOLEAN))
          case _ => Right(ClassType(name = name, unknown = unknown))
        }
    })
  val pkg: Option[JawaPackage] = base_type match {
    case Right(ClassType(Some(p), _, _)) => Some(JawaPackage(p))
    case _ => None
  }
  val name: String = base_type match {
    case Left(PrimitiveType(p)) => p.name.toLowerCase
    case Right(ClassType(_, n, _)) => n
  }
  val unknown: Boolean = base_type match {
    case Left(_) => false
    case Right(ClassType(_, _, u)) => u
  }
  /**
   * This is the internal representation for type (with package name).
   * e.g. (None, int) -> int, (java.lang, Object) -> java.lang.Object
   */
  def typ: String = {
    val namePart = name + {if(unknown) "?" else ""}
    if(pkg.isEmpty) namePart
    else pkg.get.toPkgString(".") + "." + namePart
  }
  def packageName: String = 
    if(pkg.isEmpty) ""
    else pkg.get.toPkgString(".")
  def toUnknown: JawaBaseType = if(base_type.isLeft || unknown) {
    this
  } else {
    new JawaBaseType(pkg, name, unknown = true)
  }
  def removeUnknown(): JawaBaseType = base_type match {
    case Right(un @ ClassType(_, _, true)) => this.copy(base_type = Right(un.copy(unknown = false)))
    case _ => this
  }
  override def toString: String = typ
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
case class JawaType(javaType: JavaType) {
  def this(baseType: JawaBaseType, dimensions: Int) = this(baseType.base_type  match {
    case Left(p) => JavaType(baseType = BaseType.PrimitiveType(p), dimension = dimensions)
    case Right(c) => JavaType(baseType = BaseType.ClassType(c), dimension = dimensions)
  })
  def this(baseType: JawaBaseType) = this(baseType, 0)
  def this(pkgAndTyp: String, dimensions: Int = 0) = this(JavaKnowledge.separatePkgAndTyp(pkgAndTyp), dimensions)

  val baseType: JawaBaseType = {
    javaType.baseType match {
      case BaseType.PrimitiveType(p) => JawaBaseType(Left(p))
      case BaseType.ClassType(c) => JawaBaseType(Right(c))
      case _ => throw new RuntimeException("BaseType is wrong!")
    }
  }
  val dimensions: Int = javaType.dimension

  require(dimensions >= 0, s"Class type must have positive dimension. baseType: ${baseType.name}, dimensions: $dimensions")

  /**
   * Package will be None if it's array, primitive, no package class. e.g. int -> None, java.lang.Object -> Some("java.lang")
   * java.lang.Object[] -> None
   */
  def getPackage: Option[JawaPackage] = if(isArray) None else baseType.pkg
  def getPackageName: String = getPackage match {
    case Some(pkg) => pkg.toPkgString(".")
    case None => ""
  }
  /**
   * Type is the name of the primitive or class or arrays base class, such as: int -> int, java.lang.Object -> Object,
   * int[] -> int
   */
  def getType: String = baseType.typ
  def isArray: Boolean = dimensions > 0
  def isPrimitive: Boolean = baseType.pkg.isEmpty && JavaKnowledge.isJavaPrimitive(baseType.typ) && dimensions == 0
  def isDWordPrimitive: Boolean = isPrimitive && JavaKnowledge.JAVA_DWORD_PRIMITIVES.contains(baseType.typ)
  def isObject: Boolean = !isPrimitive
  def toUnknown: JawaType = new JawaType(baseType.toUnknown, dimensions)
  def removeUnknown(): JawaType = new JawaType(baseType.removeUnknown(), dimensions)
  /**
   * This is the internal representation for type or array base type (with package name).
   * e.g. int -> int, java.lang.Object -> java.lang.Object, java.lang.Object[] -> java.lang.Object
   * It's very tricky, use it carefully.
   */
  def baseTyp: String = {
    baseType.typ
  }
  def name: String = JavaKnowledge.formatTypeToName(this)
  def simpleName: String = {
    canonicalName.substring(canonicalName.lastIndexOf(".") + 1)
  }
  def jawaName: String = {
    val base = baseTyp
    JavaKnowledge.assign(base, dimensions, "[]", front = false)
  }
  def canonicalName: String = {
    val base = baseTyp.replaceAll("\\$", ".")
    JavaKnowledge.assign(base, dimensions, "[]", front = false)
  }

  /**
   * The result looks like:
   * input: java.lang.wfg.W$F$G$H
   * output: List(java.lang.wfg.W$F$G, java.lang.wfg.W$F, java.lang.wfg.W)
   */
  def getEnclosingTypes: List[JawaType] = {
    val result: MList[JawaType] = mlistEmpty
    if(isPrimitive || isArray) return result.toList
    else if(baseTyp.contains("$")){
      var outer = baseTyp.substring(0, baseTyp.lastIndexOf("$"))
      while(outer.contains("$")) {
        result += new JawaType(outer)
        outer = outer.substring(0, outer.lastIndexOf("$"))
      } 
      result += new JawaType(outer, 0)
    }
    result.toList
  }

  override def toString: String = name
}

case class InvalidTypeException(msg: String) extends RuntimeException(msg)
