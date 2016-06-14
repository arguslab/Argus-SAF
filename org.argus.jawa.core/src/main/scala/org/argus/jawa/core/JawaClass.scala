/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.sireum.util._

/**
 * This class is an jawa class representation of a pilar record. A JawaClass corresponds to a class or an interface of the source code. They are usually created by jawa Resolver.
 * You can also construct it manually.
 * 
 * @param global interactive compiler of this class
 * @param typ object type of this class
 * @param accessFlags the access flags integer representation for this class
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class JawaClass(global: Global, typ: JawaType, accessFlags: Int) extends JawaElement with JavaKnowledge with ResolveLevel {
  
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
   * is this class loaded or not
   */
  def isLoaded: Boolean = resolvingLevel <= ResolveLevel.NOT_LOADED
  
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
  protected val interfaces: MMap[String, JawaClass] = mmapEmpty
  
  /**
   * super class of this class. For interface it's always java.lang.Object
   */
  protected var superClass: JawaClass = null
  
  protected val unknownParents: MMap[String, JawaClass] = mmapEmpty
  
  /**
   * outer class of this class
   */
  protected var outerClass: JawaClass = null
  
  /**
   * return true if it's a child of given record
   */
  def isChildOf(typ: JawaType): Boolean = {
    isChildOf(global.getClassOrResolve(typ))
  }
  
  /**
   * return true if it's a child of given record
   */
  def isChildOf(clazz: JawaClass): Boolean = {
    global.getClassHierarchy.getAllSuperClassesOf(this).contains(clazz)
  }
  
  def isImplementerOf(typ: JawaType): Boolean = {
    isImplementerOf(global.getClassOrResolve(typ))
  }
  
  def isImplementerOf(clazz: JawaClass): Boolean = {
    global.getClassHierarchy.getAllImplementersOf(clazz).contains(this)
  }
  
  /**
   * if the class is array type return true
   */
  def isArray: Boolean = getType.isArray

  /**
   * return the number of fields declared in this class
   */
  def fieldSize = this.fields.size

  /**
   * get all the fields accessible from the class
   */
  def getFields: ISet[JawaField] = {
    var results = getDeclaredFields
    var worklist: Set[JawaClass] = Set()
    worklist += this
    while(worklist.nonEmpty){
      worklist =
        worklist.map{
          rec =>
            var parents = rec.getInterfaces
            rec.getSuperClass foreach{parents += _}
            val fields =
              if(parents.nonEmpty)
                parents.map{
                  parent =>
                    parent.getDeclaredFields.filter(f => !f.isPrivate && !results.exists(_.getName == f.getName))
                }.reduce(iunion[JawaField])
              else Set[JawaField]()
                results ++= fields
              parents
        }.reduce(iunion[JawaClass])
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
  def addField(field: JawaField) = {
    val fieldName = field.getName
    if(declaresField(fieldName)) global.reporter.warning(TITLE, "Field " + fieldName + " in class " + getName)
    else this.fields(fieldName) = field
  }

  /**
   * return true if the field is declared in this class
   */
  def declaresField(name: String): Boolean = getDeclaredFields.exists(_.getName == name)

  /**
   * return true if the field is declared in this class
   */
  def hasField(name: String): Boolean = getFields.exists(_.getName == name)

  /**
   * removes the given field from this class
   */
  def removeField(field: JawaField) = {
    if(field.getDeclaringClass != this) throw new RuntimeException(getName + " did not declare " + field.getName)
    this.fields -= field.getName
  }

  /**
   * get field from this class by the given name
   */
  def getField(name: String, typ: JawaType): Option[JawaField] = {
    if(!isValidFieldName(name)){
      global.reporter.error(TITLE, "field name is not valid " + name)
      return None
    }
    val fopt = getFields.find(_.getName == name)
    fopt match{
      case Some(f) => Some(f)
      case None => 
        if(isUnknown){
          Some(JawaField(this, name, typ, AccessFlag.getAccessFlags("PUBLIC")))
        } else {
          global.reporter.error(TITLE, "No field " + name + " in class " + getName)
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
    this.fields.get(name) match {
      case Some(f) => Some(f)
      case None =>
        println(this.fields)
        global.reporter.error(TITLE, "No field " + name + " in class " + getName)
        None
    }
  }

  /**
   * get method from this class by the given subsignature
   */
  def getMethod(subSig: String): Option[JawaMethod] = {
    this.methods.get(subSig) match{
      case Some(p) => Some(p)
      case None => 
        if(isUnknown){
          val signature = generateSignatureFromOwnerAndMethodSubSignature(this, subSig)
          Some(generateUnknownJawaMethod(this, signature))
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
          if(found) throw new RuntimeException("ambiguous method" + methodName)
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
    getDeclaredMethods.filter(method=> method.getName == methodName)
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
   * get methods of this class
   */
  def getDeclaredMethods: ISet[JawaMethod] = this.methods.values.toSet

  /**
   * get method by the given name, parameter types and return type
   */
  def getDeclaredMethod(name: String, paramTyps: List[String], returnTyp: JawaType): JawaMethod = {
    var ap: JawaMethod = null
    getDeclaredMethods.foreach{
      method=>
        if(method.getName == name && method.getParamTypes == paramTyps && method.getReturnType == returnTyp) ap = method
    }
    if(ap == null) throw new RuntimeException("In " + getName + " does not have method " + name + "(" + paramTyps + ")" + returnTyp)
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
  def addMethod(ap: JawaMethod) = {
    if(this.methods.contains(ap.getSubSignature)) 
      global.reporter.error(TITLE, "The method " + ap.getSubSignature + " is already declared in class " + getName)
    else this.methods(ap.getSubSignature) = ap
  }

  /**
   * remove the given method from this class
   */
  def removeMethod(ap: JawaMethod) = {
    if(ap.getDeclaringClass != this) global.reporter.error(TITLE, "Not correct declarer for remove: " + ap.getName)
    else if(!this.methods.contains(ap.getSubSignature)) global.reporter.error(TITLE, "The method " + ap.getName + " is not declared in class " + getName)
    else this.methods -= ap.getSubSignature
  }

  /**
   * get interface size
   */
  def getInterfaceSize: Int = this.interfaces.size

  /**
   * get interfaces
   */
  def getInterfaces: ISet[JawaClass] = this.interfaces.values.toSet

  /**
   * whether this class implements the given interface
   */
  def implementsInterface(name: String): Boolean = {
    this.interfaces.contains(name)
  }

  /**
   * add an interface which is directly implemented by this class
   */
  def addInterface(i: JawaClass) = {
    if(!i.isInterface) global.reporter.error(TITLE, "This is not an interface:" + i)
    else if(implementsInterface(i.getName)) 
      global.reporter.error(TITLE, this + " already implements interface " + i)
    else this.interfaces(i.getName) = i
  }

  /**
   * remove an interface from this class
   */
  def removeInterface(i: JawaClass) = {
    if(!i.isInterface) global.reporter.error(TITLE, "This is not an interface:" + i)
    else if(!implementsInterface(i.getName)) global.reporter.error(TITLE, this + " not implements interface " + i.getName)
    else this.interfaces -= i.getName
  }

  /**
   * whether the current class has a super class or not
   */
  def hasSuperClass = this.superClass != null

  /**
   * get the super class
   */
  def getSuperClass: Option[JawaClass] = {
    if(!hasSuperClass){
      None
    } else {
      Some(this.superClass)
    }
  }

  /**
   * set super class
   */
  def setSuperClass(sc: JawaClass) = {
    this.superClass = sc
  }
  
  def addUnknownParent(up: JawaClass) = {
    if(up.isLoaded) global.reporter.error(TITLE, "The parent class is loaded, so there are no reason to be unknown:" + up)
    else this.unknownParents(up.getName) = up
  }
  
  def getUnknownParents: ISet[JawaClass] = this.unknownParents.values.toSet

  /**
   * whether the current class has an outer class or not
   */
  def hasOuterClass = this.outerClass != null

  /**
   * get the outer class
   */
  def getOuterClass: Option[JawaClass] = {
    if(!hasOuterClass){
      None
    }
    else Some(this.outerClass)
  }

  /**
   * set outer class
   */
  def setOuterClass(oc: JawaClass) = {
    this.outerClass = oc
  }

  /**
   * whether current class is an inner class or not
   */
  def isInnerClass: Boolean = hasOuterClass

  /**
   * return true if this class is an interface
   */
  def isInterface: Boolean = AccessFlag.isInterface(this.accessFlags)
  
  /**
   * return true if this class is concrete
   */
  def isConcrete: Boolean = !isInterface && !isAbstract
  
  /**
   * is this class an application class
   */
  def isApplicationClass: Boolean = global.isApplicationClasses(getType)
  
  /**
   * set this class as an application class
   */
  def setApplicationClass() = {
    val c = global.getContainingSet(this)
    if(c != null) global.removeFromContainingSet(this)
    global.addApplicationClass(this)
  }

  /**
   * is this class  a framework class
   */
  def isSystemLibraryClass: Boolean = global.isSystemLibraryClasses(getType)
  
  /**
   * is this class  a user lib class
   */
  def isUserLibraryClass: Boolean = global.isUserLibraryClasses(getType)
  
  
  /**
   * set this class as a system library class
   */
  def setSystemLibraryClass() = {
    val c = global.getContainingSet(this)
    if(c != null) global.removeFromContainingSet(this)
    global.addSystemLibraryClass(this)
  }
  
  /**
   * set this class as a third party lib class
   */
  def setUserLibraryClass() = {
    val c = global.getContainingSet(this)
    if(c != null) global.removeFromContainingSet(this)
    global.addUserLibraryClass(this)
  }
  
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
   * Jawa AST node for this JawaClass. Unless unknown, it should not be null.
   */
//  private var classOrInterfaceDecl: ClassOrInterfaceDeclaration = null //NON-NIL
//  
//  def setAST(cid: ClassOrInterfaceDeclaration) = this.classOrInterfaceDecl = cid
//  
//  def getAST: ClassOrInterfaceDeclaration = {
//    if(isUnknown) throw new RuntimeException(getName + " is unknown class, so cannot get the AST")
//    require(this.classOrInterfaceDecl != null)
//    this.classOrInterfaceDecl
//  }
    
  /**
   * retrieve code belong to this class
   */
//def retrieveCode: String = getAST.toCode

  /**
   * set resolving level. Don't set by yourself.
   */
  def setResolvingLevel(level: ResolveLevel.Value) = {
    this.resolvingLevel = level
  }
  
  /**
   * update resolving level for current class
   */
  def updateResolvingLevel() = {
    setResolvingLevel(getDeclaredMethods.map(_.getResolvingLevel).reduceLeft((x, y) => if(x < y) x else y))
  }

  def printDetail() = {
    println("++++++++++++++++AmandroidClass++++++++++++++++")
    println("recName: " + getName)
    println("package: " + getPackage)
    println("simpleName: " + getSimpleName)
    println("CanonicalName: " + getCanonicalName)
    println("superClass: " + getSuperClass)
    println("outerClass: " + getOuterClass)
    println("interfaces: " + getInterfaces)
    println("accessFlags: " + getAccessFlagsStr)
    println("isLoaded: " + isLoaded)
    println("fields: " + getDeclaredFields)
    println("methods: " + getDeclaredMethods)
    println("++++++++++++++++++++++++++++++++")
  }

  override def toString: String = getName
  
  this.global.addClassInternal(this)
}
