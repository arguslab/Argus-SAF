/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.elements._
import org.argus.jawa.core.util._

/**
 * This class is an jawa class representation of a jawa record. A JawaClass corresponds to a class or an interface of the source code. They are usually created by jawa Resolver.
 * You can also construct it manually.
 *
 * @param global interactive compiler of this class
 * @param typ object type of this class
 * @param accessFlags the access flags integer representation for this class
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class JawaClass(global: Global, typ: JawaType, accessFlags: Int) extends JawaElement with JavaKnowledge {

  final val TITLE = "JawaClass"

  def this(global: Global, typ: JawaType, accessStr: String) = {
    this(global, typ, AccessFlag.getAccessFlags(accessStr))
  }

  require(typ.isObject, "JawaClass should be object type, but get: " + typ)

  def getType: JawaType = this.typ

  /**
   * full name of this class: java.lang.Object or [Ljava.lang.Object;
   */
  def getName: String = getType.name
  /**
   * simple name of this class: Object or Object[]
   */
  def getSimpleName: String = getType.simpleName
  /**
   * canonical name of this class: java.lang.Object or java.lang.Object[]
   */
  def getCanonicalName: String = getType.canonicalName
  /**
   * package name of this class: java.lang
   */
  def getPackage: Option[JawaPackage] = getType.getPackage

  /**
   * set of fields which declared in this class. map from field name to JawaField
   */
  protected val fields: MMap[String, JawaField] = mmapEmpty

  /**
   * set of methods which belong to this class. map from subsig to JawaMethod
   */
  protected val methods: MMap[String, JawaMethod] = mmapEmpty

  /**
   * set of interfaces which this class/interface implements/extends. map from interface name to JawaClass
   */
  protected val interfaces: MSet[JawaClass] = msetEmpty

  /**
   * super class of this class.
   */
  protected var superClass: JawaClass = _

  /**
   * return true if it's a child of given record
   */
  def isChildOf(typ: JawaType): Boolean = {
    var sc = this
    while(sc.hasSuperClass) {
      sc = sc.getSuperClass
      if(sc.getType == typ) return true
    }
    false
  }

  def isImplementerOf(typ: JawaType): Boolean = {
    global.getClassHierarchy.getAllImplementersOf(global.getClassOrResolve(typ)).contains(this)
  }

  /**
   * if the class is array type return true
   */
  def isArray: Boolean = getType.isArray

  /**
   * return the number of fields declared in this class
   */
  def fieldSize: Int = this.fields.size

  /**
   * get all the fields accessible from the class
   */
  def getFields: ISet[JawaField] = {
    var results = getDeclaredFields
    var rec = this
    while(rec.hasSuperClass){
      val parent = rec.getSuperClass
      val fields = parent.getDeclaredFields.filter(f => !f.isPrivate && !results.exists(_.getName == f.getName))
      results ++= fields
      rec = parent
    }
    results
  }

  /**
   * get all the fields declared in this class
   */
  def getDeclaredFields: ISet[JawaField] = this.fields.values.toSet

  /**
   * get all static fields of the class
   */
  def getStaticFields: ISet[JawaField] = getFields.filter(f => f.isStatic)

  /**
   * get all non-static fields of the class
   */
  def getNonStaticFields: ISet[JawaField] = getFields.filter(f => !f.isStatic)

  /**
   * get all object type field
   */
  def getObjectTypeFields: ISet[JawaField] = getFields.filter(f => f.isObject)

  /**
   * get all non static and object type field
   */
  def getNonStaticObjectTypeFields: ISet[JawaField] = getNonStaticFields.intersect(getObjectTypeFields)

  /**
   * get all static and object type field
   */
  def getStaticObjectTypeFields: ISet[JawaField] = getStaticFields.intersect(getObjectTypeFields)

  /**
   * get all static fields of the class
   */
  def getDeclaredStaticFields: ISet[JawaField] = getDeclaredFields.filter(f => f.isStatic)

  /**
   * get all non-static fields of the class
   */
  def getDeclaredNonStaticFields: ISet[JawaField] = getDeclaredFields.filter(f => !f.isStatic)

  /**
   * get all object type field
   */
  def getDeclaredObjectTypeFields: ISet[JawaField] = getDeclaredFields.filter(f => f.isObject)

  /**
   * get all non static and object type field
   */
  def getDeclaredNonStaticObjectTypeFields: ISet[JawaField] = getDeclaredNonStaticFields.intersect(getDeclaredObjectTypeFields)

  /**
   * get all static and object type field
   */
  def getDeclaredStaticObjectTypeFields: ISet[JawaField] = getDeclaredStaticFields.intersect(getDeclaredObjectTypeFields)

  /**
   * add one field into the class
   */
  def addField(field: JawaField): Unit = {
    val fieldName = field.getName
    if(declaresField(fieldName)) global.reporter.warning(TITLE, "Field " + fieldName + " already in class " + getName)
    else this.fields(fieldName) = field
  }

  /**
   * return true if the field is declared in this class
   */
  def declaresField(name: String): Boolean = fields.contains(name)

  /**
   * return true if the field is declared in this class
   */
  def hasField(name: String): Boolean = getFields.exists(_.getName == name)

  /**
   * removes the given field from this class
   */
  def removeField(field: JawaField): fields.type = {
    if(field.getDeclaringClass != this) throw new RuntimeException(getName + " did not declare " + field.getName)
    this.fields -= field.getName
  }

  /**
   * get field from this class by the given name
   */
  def getField(name: String, typ: JawaType): Option[JawaField] = {
    val field = getDeclaredField(name) match {
      case Some(f) if f.typ == typ => Some(f)
      case _ =>
        if(hasSuperClass) {
          getSuperClass.getField(name, typ)
        } else {
          None
        }
    }
    field match {
      case f @ Some(_) => f
      case None =>
        if(isUnknown){
          Some(JawaField(this, name, typ, AccessFlag.getAccessFlags("PUBLIC")))
        } else {
          None
        }
    }
  }

  /**
    * get field from this class by the given name
    */
  def getField(name: String): Option[JawaField] = {
    getDeclaredField(name) match {
      case f @ Some(_) => f
      case None =>
        if(hasSuperClass) {
          getSuperClass.getField(name)
        } else {
          None
        }
    }
  }

  /**
   * get field declared in this class by the given name
   */
  def getDeclaredField(name: String): Option[JawaField] = {
    if(!isValidFieldName(name)){
      global.reporter.error(TITLE, "field name is not valid " + name)
      return None
    }
    this.fields.get(name)
  }

  /**
    * get method from this class by the given subsignature
    */
  def getMethod(subSig: String): Option[JawaMethod] = {
    getDeclaredMethod(subSig) match {
      case m @ Some(_) => m
      case None =>
        if(hasSuperClass) {
          getSuperClass.getMethod(subSig)
        } else {
          if(isUnknown){
            val signature = generateSignatureFromOwnerAndMethodSubSignature(getType, subSig)
            Some(this.generateUnknownJawaMethod(signature))
          } else None
        }
    }
  }

  def generateUnknownJawaMethod(signature: Signature): JawaMethod = {
    val name = signature.methodName
    val thisOpt: Option[String] = Some("unknownThis")
    val paramTypes: IList[JawaType] = signature.getParameterTypes
    val params: ISeq[(String, JawaType)] = Array.tabulate(paramTypes.length){ i => ("unknownParam" + i, paramTypes(i)) }.toList
    val returnType: JawaType = signature.getReturnType
    val accessFlags = AccessFlag.getAccessFlags("PUBLIC")
    val method = JawaMethod(this, name, thisOpt, params, returnType, accessFlags)
    method.setUnknown()
    method
  }

  /**
    * get method from this class by the given method name
    */
  def getMethodsByName(methodName: String): Set[JawaMethod] = {
    getMethods.filter(method => method.getName == methodName)
  }

  def getMethodByNameAndArgTypes(name: String, argTypes: IList[JawaType]): Option[JawaMethod] = {
    getDeclaredMethodsByName(name).find { m =>
      m.matches(name, argTypes)
    } match {
      case m @ Some(_) => m
      case None =>
        if(hasSuperClass) {
          getSuperClass.getMethodByNameAndArgTypes(name, argTypes)
        } else None
    }
  }

  /**
   * get method from this class by the given subsignature
   */
  def getDeclaredMethod(subSig: String): Option[JawaMethod] = {
    this.methods.get(subSig) match{
      case Some(p) => Some(p)
      case None =>
        if(isUnknown){
          val signature = generateSignatureFromOwnerAndMethodSubSignature(getType, subSig)
          Some(this.generateUnknownJawaMethod(signature))
        } else None
    }
  }

  /**
   * get method from this class by the given name
   */
  def getDeclaredMethodByName(methodName: String): Option[JawaMethod] = {
    if(!declaresMethodByName(methodName)){
      global.reporter.error(TITLE, "No method " + methodName + " in class " + getName)
      return None
    }
    var found = false
    var foundMethod: JawaMethod = null
    getDeclaredMethods.foreach{
      proc=>
        if(proc.getName == methodName){
          if(found) throw new RuntimeException("ambiguous method " + methodName)
          else {
            found = true
            foundMethod = proc
          }
        }
    }
    if(found) Some(foundMethod)
    else {
      global.reporter.error(TITLE, "couldn't find method " + methodName + "(*) in " + this)
      None
    }
  }

  /**
   * get method from this class by the given method name
   */
  def getDeclaredMethodsByName(methodName: String): Set[JawaMethod] = {
    getDeclaredMethods.filter(method => method.getName == methodName)
  }

  /**
   * get static initializer of this class
   */
  def getStaticInitializer: Option[JawaMethod] = getDeclaredMethodByName(this.staticInitializerName)

  /**
   * whether this method exists in the class or not
   */
  def declaresMethod(subSig: String): Boolean = this.methods.contains(subSig)

  /**
   * get method size of this class
   */
  def getMethodSize: Int = this.methods.size

  /**
    * get all the methods accessible from the class
    */
  def getMethods: ISet[JawaMethod] = {
    val results: MSet[JawaMethod] = msetEmpty ++ getDeclaredMethods
    var rec = this
    while(rec.hasSuperClass){
      val parent = rec.getSuperClass
      val ms = parent.getDeclaredMethods.filter(m => !m.isPrivate && !results.exists(_.getSubSignature == m.getSubSignature))
      results ++= ms
      rec = parent
    }
    results.toSet
  }

  /**
   * get methods of this class
   */
  def getDeclaredMethods: ISet[JawaMethod] = this.methods.values.toSet

  /**
   * get method by the given name, parameter types and return type
   */
  def getDeclaredMethod(name: String, paramTypes: List[String], returnTyp: JawaType): JawaMethod = {
    var ap: JawaMethod = null
    getDeclaredMethods.foreach{ method=>
      if(method.getName == name && method.getParamTypes == paramTypes && method.getReturnType == returnTyp) ap = method
    }
    if(ap == null) throw new RuntimeException("In " + getName + " does not have method " + name + "(" + paramTypes + ")" + returnTyp)
    else ap
  }

  /**
   * does method exist with the given name, parameter types and return type?
   */
  def declaresMethod(name: String, paramTyps: List[String], returnTyp: JawaType): Boolean = {
    var find: Boolean = false
    getDeclaredMethods.foreach{
      method=>
        if(method.getName == name && method.getParamTypes == paramTyps && method.getReturnType == returnTyp) find = true
    }
    find
  }

  /**
   * does method exist with the given name and parameter types?
   */
  def declaresMethod(name: String, paramTyps: List[String]): Boolean = {
    var find: Boolean = false
    getDeclaredMethods.foreach{
      method=>
        if(method.getName == name && method.getParamTypes == paramTyps) find = true
    }
    find
  }

  /**
   * does method exists with the given name?
   */
  def declaresMethodByName(name: String): Boolean = {
    getDeclaredMethods exists (_.getName == name)
  }

  /**
   * return true if this class has static initializer
   */
  def declaresStaticInitializer: Boolean = declaresMethodByName(this.staticInitializerName)

  /**
   * add the given method to this class
   */
  def addMethod(ap: JawaMethod): Unit = {
    if(this.methods.contains(ap.getSubSignature))
      global.reporter.error(TITLE, "The method " + ap.getSubSignature + " is already declared in class " + getName)
    else this.methods(ap.getSubSignature) = ap
  }

  /**
   * remove the given method from this class
   */
  def removeMethod(ap: JawaMethod): Any = {
    if(ap.getDeclaringClass != this) global.reporter.error(TITLE, "Not correct declarer for remove: " + ap.getName)
    else if(!this.methods.contains(ap.getSubSignature)) global.reporter.error(TITLE, "The method " + ap.getName + " is not declared in class " + getName)
    else this.methods -= ap.getSubSignature
  }

  /**
    * get static methods
    */
  def getStaticMethods: ISet[JawaMethod] = getMethods.filter(m => m.isStatic)

  /**
   * get interface size
   */
  def getInterfaceSize: Int = this.interfaces.size

  /**
   * get interfaces
   */
  def getInterfaces: ISet[JawaClass] = this.interfaces.toSet

  /**
   * whether this class implements the given interface
   */
  def implementsInterface(typ: JawaType): Boolean = this.interfaces.map(_.getType).contains(typ)

  /**
   * add an interface which is directly implemented by this class
   */
  def addInterface(i: JawaClass): Unit = {
    this.interfaces += i
  }

  /**
   * remove an interface from this class
   */
  def removeInterface(i: JawaClass): Any = {
    this.interfaces -= i
  }

  /**
   * whether the current class has a super class or not
   */
  def hasSuperClass: Boolean = this.superClass != null

  /**
   * get the super class
   */
  def getSuperClass: JawaClass = this.superClass

  /**
   * set super class
   */
  def setSuperClass(sc: JawaClass): Unit = this.superClass = sc

  /**
   * whether the current class has an outer class or not
   */
  def hasOuterType: Boolean = isInnerClass(getType)

  /**
   * get the outer class
   */
  def getOuterType: Option[JawaType] = if(isInnerClass) Some(getOuterTypeFrom(getType)) else None

  /**
   * whether current class is an inner class or not
   */
  def isInnerClass: Boolean = hasOuterType

  /**
    * return all parents of this class
    */
  def getAllParents: ISet[JawaClass] = {
    val parents: MSet[JawaClass] = msetEmpty
    if(hasSuperClass) {
      parents += getSuperClass
      parents ++= getSuperClass.getAllParents
    }
    parents ++= getInterfaces
    getInterfaces.foreach{ i =>
      parents ++= i.getAllParents
    }
    parents.toSet
  }

  /**
   * return true if this class is an interface
   */
  def isInterface: Boolean = AccessFlag.isInterface(this.accessFlags)

  /**
   * return true if this class is concrete
   */
  def isConcrete: Boolean = !isInterface && !isAbstract && !isUnknown

  /**
   * is this class an application class
   */
  def isApplicationClass: Boolean = global.isApplicationClasses(getType.removeUnknown())

  /**
   * is this class  a framework class
   */
  def isSystemLibraryClass: Boolean = global.isSystemLibraryClasses(getType.removeUnknown())

  /**
   * is this class  a user lib class
   */
  def isUserLibraryClass: Boolean = global.isUserLibraryClasses(getType.removeUnknown())

  /**
   * whether this class is a java library class
   */
  def isJavaLibraryClass: Boolean = {
    val packageName = getPackage match {
      case Some(pkg) => pkg.toPkgString(".")
      case None => ""
    }
    packageName.startsWith("java.") ||
    packageName.startsWith("sun.") ||
    packageName.startsWith("javax.") ||
    packageName.startsWith("com.sun.") ||
    packageName.startsWith("org.omg.") ||
    packageName.startsWith("org.xml.")
  }

  /**
    * Determines if the class or interface represented by this
    * `JawaClass` object is either the same as, or is a superclass or
    * superinterface of, the class or interface represented by the specified
    * `JawaClass` parameter. It returns `true` if so;
    * otherwise it returns `false`.
    *
    * @param other the { @code Class} object to be checked
    * @return the { @code boolean} value indicating whether objects of the
    *                     type { @code other} can be assigned to objects of this class
    */
  def isAssignableFrom(other: JawaClass): Boolean = {
    if(other == null) false
    else if(getType.removeUnknown() == other.getType) true
    else if(isInterface && other.isInterface) {
      other.getInterfaces.exists(isAssignableFrom)
    } else if(isInterface && !other.isInterface) {
      var tmp = other
      var found = false
      while(!found && tmp.hasSuperClass) {
        found = tmp.getInterfaces.exists(isAssignableFrom)
        tmp = tmp.getSuperClass
      }
      found
    } else if(!isInterface && other.isInterface) {
      getType.removeUnknown() == JavaKnowledge.OBJECT
    } else {
      isAssignableFrom(other.getSuperClass)
    }
  }

  def printDetail(): Unit = {
    println("++++++++++++++++JawaClass++++++++++++++++")
    println("recName: " + getName)
    println("package: " + getPackage)
    println("simpleName: " + getSimpleName)
    println("CanonicalName: " + getCanonicalName)
    println("superClass: " + getSuperClass)
    println("outerType: " + getOuterType)
    println("interfaces: " + getInterfaces)
    println("accessFlags: " + getAccessFlagsStr)
    println("fields: " + getDeclaredFields)
    println("methods: " + getDeclaredMethods)
    println("++++++++++++++++++++++++++++++++")
  }

  override def toString: String = getName
}
