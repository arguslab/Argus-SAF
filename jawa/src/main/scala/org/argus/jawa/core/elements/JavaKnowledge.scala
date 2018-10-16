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

import org.argus.jawa.core.util._

trait JavaKnowledge {

  def JAVA_PRIMITIVES: ISet[String] = Set("byte", "short", "int", "float", "boolean", "char") ++ JAVA_DWORD_PRIMITIVES
  def JAVA_DWORD_PRIMITIVES = Set("long", "double")

  /**
    * return whether given type is java primitive type
    */
  def isJavaPrimitive(name: String): Boolean = this.JAVA_PRIMITIVES.contains(name)

  /**
    * return whether given type is java dword primitive type
    */
  def isJavaDwordPrimitive(name: String): Boolean = this.JAVA_DWORD_PRIMITIVES.contains(name)

  object ClassCategory extends Enumeration {
    val APPLICATION, USER_LIBRARY, SYSTEM_LIBRARY = Value
  }
  
  def formatTypeToName(typ: JawaType): String = {
    val d = typ.dimensions
    if(d <= 0) return typ.baseTyp
    typ.baseTyp match{
      case "byte" =>    assign("B", d, "[", front = true)
      case "char" =>    assign("C", d, "[", front = true)
      case "double" =>  assign("D", d, "[", front = true)
      case "float" =>   assign("F", d, "[", front = true)
      case "int" =>     assign("I", d, "[", front = true)
      case "long" =>    assign("J", d, "[", front = true)
      case "short" =>   assign("S", d, "[", front = true)
      case "boolean" => assign("Z", d, "[", front = true)
      case _ =>
        assign("L" + typ.baseTyp + ";", d, "[", front = true)
    }
  }
  
  def formatTypeToSignature(typ: JawaType): String = {
    val d = typ.dimensions
    typ.baseTyp match{
      case "byte" =>    assign("B", d, "[", front = true)
      case "char" =>    assign("C", d, "[", front = true)
      case "double" =>  assign("D", d, "[", front = true)
      case "float" =>   assign("F", d, "[", front = true)
      case "int" =>     assign("I", d, "[", front = true)
      case "long" =>    assign("J", d, "[", front = true)
      case "short" =>   assign("S", d, "[", front = true)
      case "boolean" => assign("Z", d, "[", front = true)
      case "void" =>    "V"
      case _ =>
        assign("L" + typ.baseTyp.replaceAll("\\.", "/") + ";", d, "[", front = true)
    }
  }
  
  /**
   * input: "[Ljava/lang/String;"  output: ("Ljava/lang/String;", 1)
   */
  private def getDimensionsAndRemoveArrayFromSig(sig: String): (String, Int) = {
    val d = if(sig.startsWith("[")) {
      sig.lastIndexOf('[') - sig.indexOf('[') + 1
    } else {
      0
    }
    val tmp = sig.substring(sig.lastIndexOf('[') + 1)
    (tmp, d)
  }
  
  /**
   * input: "java.lang.String"  output: (Some("java.lang"), "String")
   * input: "int" output: (None, "int")
   */
  def separatePkgAndTyp(pkgAndTyp: String): JawaBaseType = {
    if(isJavaPrimitive(pkgAndTyp)) return new JawaBaseType(None, pkgAndTyp)
    val parts = pkgAndTyp.split("\\.")
    val size = parts.size
    var currentPkg: Option[JawaPackage] = None
    for(i <- 0 to size - 2) {
      currentPkg = Some(new JawaPackage(parts(i), currentPkg))
    }
    var name = parts(size - 1)
    val unknown = if(name.endsWith("?")) true else false
    if(unknown) name = name.substring(0, name.length - 1)
    new JawaBaseType(currentPkg, name, unknown)
  }
  
  def formatPackageStringToPackage(pkg: String): JawaPackage = {
    val parts = pkg.split("\\.")
    val size = parts.size
    var currentPkg: Option[JawaPackage] = None
    for(i <- 0 until size) {
      currentPkg = Some(new JawaPackage(parts(i), currentPkg))
    }
    currentPkg.get
  }
  
  /**
   * input ("java.lang.String", 1) output Type
   */
  protected def getType(typ: String, dimensions: Int): JawaType = {
    new JawaType(typ, dimensions)
  }
  
  /**
   * input: "java.lang.String[]"  output: JawaType("java.lang.String", 1)
   */
  def getTypeFromJawaName(name: String): JawaType = {
    var d: Int = 0
    var tmp = name
    while(tmp.endsWith("[]")){
      d += 1
      tmp = tmp.substring(0, tmp.length() - 2)
    }
    getType(tmp, d)
  }

  /**
    * input: "[Ljava.lang.String;"  output: JawaType("java.lang.String", 1)
    */
  def getTypeFromName(name: String): JawaType = {
    var d: Int = 0
    var tmp = name
    while(tmp.startsWith("[")){
      d += 1
      tmp = tmp.substring(1, tmp.length())
    }
    tmp = tmp match{
      case "B" =>    "byte"
      case "C" =>    "char"
      case "F" =>    "float"
      case "I" =>    "int"
      case "J" =>    "long"
      case "S" =>    "short"
      case "Z" =>    "boolean"
      case "V" =>    "void"
      case _ =>
        if(d > 0) tmp.substring(1, tmp.length - 1)
        else tmp
    }
    getType(tmp, d)
  }

  /**
   * convert type string from signature style to type. [Ljava/lang/Object; -> (java.lang.Object, 1)
   */
  def formatSignatureToType(sig: String): JawaType = {
    val (tmp, d) = getDimensionsAndRemoveArrayFromSig(sig)
    tmp match{
      case "B" =>   getType("byte", d)
      case "C" =>   getType("char", d)
      case "D" =>   getType("double", d)
      case "F" =>   getType("float", d)
      case "I" =>   getType("int", d)
      case "J" =>   getType("long", d)
      case "S" =>   getType("short", d)
      case "Z" =>   getType("boolean", d)
      case "V" =>   new JawaType("void")
      case _ =>
        getType(tmp.substring(1, tmp.length() - 1).replaceAll("\\/", "."), d)
    }
  }

  /**
   * get outer class name from inner class name. e.g. android.os.Handler$Callback -> android.os.Handler
   */
  def getOuterTypeFrom(innerType: JawaType): JawaType = {
    if(!isInnerClass(innerType)) throw InvalidTypeException("wrong innerType: " + innerType)
    new JawaType(innerType.name.substring(0, innerType.name.lastIndexOf("$")))
  }

  /**
   * return true if the given typ is a inner class or not
   */
  def isInnerClass(typ: JawaType): Boolean = !typ.isArray && typ.name.lastIndexOf("$") > 0

  /**
   * input ("Ljava/lang/String;", 1, "[", true) output "[Ljava/lang/String;"
   */
  protected[jawa] def assign(str: String, dimension: Int, pattern: String, front: Boolean): String = {
    val sb = new StringBuffer
    if(front){
      for(_ <- 1 to dimension) sb.append(pattern)
    }
    sb.append(str)
    if(!front){
      for(_ <- 1 to dimension) sb.append(pattern)
    }
    sb.toString.intern()
  }

  def genSignature(classSigPart: String, methodNamePart: String, paramSigPart: String): Signature = {
    new Signature((classSigPart + "." + methodNamePart + ":" + paramSigPart).trim)
  }

  def genSignature(classTyp: JawaType, methodName: String, paramTyps: IList[JawaType], retTyp: JawaType): Signature = {
    val paramPartSB = new StringBuilder
    paramTyps foreach{
      pTyp =>
        paramPartSB.append(formatTypeToSignature(pTyp))
    }
    val retPart = formatTypeToSignature(retTyp)
    val proto = "(" + paramPartSB.toString + ")" + retPart
    new Signature(classTyp, methodName, proto)
  }

  /********************** JawaField related op **************************/

  /**
   * check if given string is field signature or not
   */
  def isFQN(str: String): Boolean = isValidFieldFQN(str)

  /**
   * generate signature of this field. input: ("java.lang.Throwable", "stackState") output: "java.lang.Throwable.stackState"
   */
  def generateFieldFQN(owner: JawaType, name: String, typ: JawaType): FieldFQN = {
    new FieldFQN(owner, name, typ)
  }

  /**
   * FQN of the field. e.g. java.lang.Throwable.stackState or @@java.lang.Enum.sharedConstantsCache
   */
  def isValidFieldFQN(fqn: String): Boolean = !fqn.startsWith("@@") && fqn.lastIndexOf('.') > 0

  /**
   * FQN of the field. e.g. java.lang.Throwable.stackState or @@java.lang.Enum.sharedConstantsCache
   */
  def isValidFieldName(name: String): Boolean = !name.contains('.')

  /**
   * get field name from field FQN. e.g. java.lang.Throwable.stackState -> stackState
   */
  def getFieldNameFromFieldFQN(fqn: String): String = {
    if(fqn == "length") fqn
    else if(!isValidFieldFQN(fqn)) throw new RuntimeException("given field signature is not a valid form: " + fqn)
    else fqn.substring(fqn.lastIndexOf('.') + 1)
  }

  /**
   * get class name from field signature. e.g. java.lang.Throwable.stackState -> java.lang.Throwable
   * [Ljava.lang.String;.length -> [Ljava.lang.String;
   */
  def getClassTypeFromFieldFQN(fqn: String): JawaType = {
    val cn = getClassNameFromFieldFQN(fqn)
    getTypeFromName(cn)
  }

  /**
   * get class name from field signature. e.g. java.lang.Throwable.stackState -> java.lang.Throwable
   * [Ljava.lang.String;.length -> [Ljava.lang.String;
   */
  def getClassNameFromFieldFQN(fqn: String): String = {
    if(!isValidFieldFQN(fqn)) throw new RuntimeException("given field signature is not a valid form: " + fqn)
    fqn.substring(0, fqn.lastIndexOf('.'))
  }
  /********************** JawaField related op end **************************/

  /********************** JawaMethod related op **************************/

  /**
   * e.g. java.lang.Throwable.run
   */
  def isValidMethodFullName(mfn: String): Boolean = mfn.lastIndexOf('.') > 0

  def getClassNameFromMethodFullName(mfn: String): String = {
    if(!isValidMethodFullName(mfn)) throw new RuntimeException("given method full name is not a valid form: " + mfn)
    else mfn.substring(mfn.lastIndexOf('.') + 1)
  }

  def getClassTypeFromMethodFullName(mfn: String): JawaType = {
    val cn = getClassNameFromMethodFullName(mfn)
    getTypeFromJawaName(cn)
  }
  
  def getMethodNameFromMethodFullName(mfn: String): String = {
    if(!isValidMethodFullName(mfn)) throw new RuntimeException("given method full name is not a valid form: " + mfn)
    else mfn.substring(mfn.lastIndexOf('.') + 1)
  }
  
  def generateSignatureFromOwnerAndMethodSubSignature(typ: JawaType, subSig: String): Signature = {
    val sig = formatTypeToSignature(typ) + "." + subSig
    new Signature(sig)
  }

  /********************** JawaMethod related op end **************************/
  
  def constructorName: String = "<init>"
  def staticInitializerName: String = "<clinit>"
  def isJawaConstructor(name: String): Boolean = name == constructorName || name == staticInitializerName
}

object JavaKnowledge extends JavaKnowledge {
  def BYTE: JawaType = new JawaType("byte")
  def SHORT: JawaType = new JawaType("short")
  def INT: JawaType = new JawaType("int")
  def FLOAT: JawaType = new JawaType("float")
  def BOOLEAN: JawaType = new JawaType("boolean")
  def CHAR: JawaType = new JawaType("char")
  def VOID: JawaType = new JawaType("void")
  def LONG: JawaType = new JawaType("long")
  def DOUBLE: JawaType = new JawaType("double")
  def CLASS: JawaType = new JawaType("java.lang.Class")
  def STRING: JawaType = new JawaType("java.lang.String")
  def THREAD: JawaType = new JawaType("java.lang.Thread")
  def OBJECT: JawaType = new JawaType("java.lang.Object")
}
