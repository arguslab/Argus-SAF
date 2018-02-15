/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.util._

object JawaType {
  def generateType(typ: String, dimensions: Int): JawaType = {
    new JawaType(typ, dimensions)
  }
  
  def addDimensions(typ: JawaType, dimensions: Int): JawaType = {
    if(typ.dimensions + dimensions >= 0) {
      JawaType(typ.baseType, typ.dimensions + dimensions)
    } else typ
  }
}

final case class JawaBaseType(pkg: Option[JawaPackage], name: String, unknown: Boolean = false) {
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
  def toUnknown: JawaBaseType = if(JavaKnowledge.isJavaPrimitive(typ)) {
    this
  } else {
    JawaBaseType(pkg, name, unknown = true)
  }
  def removeUnknown(): JawaBaseType = JawaBaseType(pkg, name)
  override def toString: String = typ
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
case class JawaType(baseType: JawaBaseType, dimensions: Int) {
  def this(baseType: JawaBaseType) = this(baseType, 0)
  def this(pkg: Option[JawaPackage], typ: String) = this(JawaBaseType(pkg, typ), 0)
  def this(pkgAndTyp: String, dimensions: Int) = this(JavaKnowledge.separatePkgAndTyp(pkgAndTyp), dimensions)
  def this(pkgAndTyp: String) = this(pkgAndTyp, 0)

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
  def toUnknown: JawaType = JawaType(baseType.toUnknown, dimensions)
  def removeUnknown(): JawaType = JawaType(baseType.removeUnknown(), dimensions)
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
