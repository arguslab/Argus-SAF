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
import com.google.common.cache.LoadingCache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.Cache

trait JawaClassLoadManager extends JavaKnowledge with JawaResolver { self: Global =>
  private final val TITLE = "JawaClassLoadManager"
  
  /**
   * set of classes contained by the current Global
   */
  protected val classes: MMap[JawaType, JawaClass] = mmapEmpty
  
  /**
   * set of application classes contained by the current Global
   */
  protected val applicationClasses: MMap[JawaType, JawaClass] = mmapEmpty
  
  /**
   * set of system library classes contained by the current Global
   */
  protected val systemLibraryClasses: MMap[JawaType, JawaClass] = mmapEmpty
  
  /**
   * set of third party lib classes contained by the current Global
   */
  protected val userLibraryClasses: MMap[JawaType, JawaClass] = mmapEmpty
  
  protected def getClassCategory(typ: JawaType): ClassCategory.Value = {
    this.applicationClasses.contains(typ) match {
      case true => ClassCategory.APPLICATION
      case false =>
        this.userLibraryClasses.contains(typ) match {
          case true => ClassCategory.USER_LIBRARY
          case false =>
            ClassCategory.SYSTEM_LIBRARY
        }
    }
  }
  
  /**
   * class hierarchy of all classes in the current Global
   */
  protected val hierarchy: ClassHierarchy = new ClassHierarchy(reporter)

  /**
   * get all the application classes
   */
  def getApplicationClasses: ISet[JawaClass] = this.applicationClasses.values.toSet
  
  /**
   * get all the system library classes
   */
  def getSystemLibraryClasses: ISet[JawaClass] = this.systemLibraryClasses.values.toSet
  
  /**
   * get all the third party lib classes
   */
  def getUserLibraryClasses: ISet[JawaClass] = this.userLibraryClasses.values.toSet
  
  /**
   * get all the application classes
   */
  def isApplicationClasses(typ: JawaType): Boolean = this.applicationClasses.contains(typ)
  
  /**
   * get all the system library classes
   */
  def isSystemLibraryClasses(typ: JawaType): Boolean = this.systemLibraryClasses.contains(typ)
  
  /**
   * get all the third party lib classes
   */
  def isUserLibraryClasses(typ: JawaType): Boolean = this.userLibraryClasses.contains(typ)
  
  /**
   * add an application class
   */
  def addApplicationClass(ar: JawaClass) = {
    if(this.applicationClasses.contains(ar.getType)) reporter.error(TITLE, "class " + ar.getName + " already exists in application class set.")
    else this.applicationClasses(ar.getType) = ar
  }
  
  /**
   * add a system library class
   */
  def addSystemLibraryClass(l: JawaClass) = {
    if(this.systemLibraryClasses.contains(l.getType)) reporter.error(TITLE, "class " + l.getName + " already exists in system library class set.")
    else this.systemLibraryClasses(l.getType) = l
  }
  
  /**
   * add a third party library class
   */
  def addUserLibraryClass(l: JawaClass) = {
    if(this.userLibraryClasses.contains(l.getType)) reporter.error(TITLE, "class " + l.getName + " already exists in user lib class set.")
    else this.userLibraryClasses(l.getType) = l
  }
  
  /**
   * get classes
   */
  def getClasses: ISet[JawaClass] = this.classes.values.toSet
  
  /**
   * Resolve all application classes to Hierarchy level. Be careful, it will take some time.
   */
  def resolveAllApplicationClasses() = {
    this.applicationClassCodes foreach {
      case (typ, sf) =>
        getClassOrResolve(typ)
    }
  }
  
  protected val classCache: LoadingCache[JawaType, JawaClass] = CacheBuilder.newBuilder()
    .maximumSize(1000).build(
        new CacheLoader[JawaType, JawaClass]() {
          def load(typ: JawaType): JawaClass = {
            classes.get(typ) match {
              case Some(c) => c
              case None =>
                resolveToHierarchy(typ)
            }
          }
        })
        
  protected val methodCache: Cache[Signature, JawaMethod] = CacheBuilder.newBuilder()
    .maximumSize(100).build()
  
  /**
   * get class by type; if it does not exist, return None
   */
  def getClazz(typ: JawaType): Option[JawaClass] = {
    Option(classCache.getIfPresent(typ)) match {
      case a @ Some(c) => a
      case None =>
        val c = this.classes.get(typ)
        if(c.isDefined) classCache.put(typ, c.get)
        c
    }
  }
  
  /**
   * get class by type, if not present resolve it, if it still not exist, return None
   */
  def getClassOrResolve(typ: JawaType): JawaClass = {
    classCache.get(typ)
  }
  
  
  protected[jawa] def getClassOrResolveWithoutCache(typ: JawaType): JawaClass = {
    classes.get(typ) match {
      case Some(c) => c
      case None =>
        resolveToHierarchy(typ)
    }
  }
  
  def tryLoadClass(typ: JawaType): Option[JawaClass] = {
    containsClassFile(typ) match {
      case true => Some(getClassOrResolve(typ))
      case false => None
    }
  }
  
  /**
   * remove application class
   */
  def removeApplicationClass(ar: JawaClass) = {
    if(!this.applicationClasses.contains(ar.getType)) reporter.error(TITLE, "class " + ar.getName + " does not exist in application class set.")
    else this.applicationClasses -= ar.getType
  }
  
  /**
   * remove System Library Class
   */
  def removeSystemLibraryClass(l: JawaClass) = {
    if(!this.systemLibraryClasses.contains(l.getType)) reporter.error(TITLE, "class " + l.getType + " does not exist in framework class set.")
    else this.systemLibraryClasses -= l.getType
  }
  
  /**
   * remove third party lib class
   */
  def removeUserLibraryClass(l: JawaClass) = {
    if(!this.userLibraryClasses.contains(l.getType)) reporter.error(TITLE, "class " + l.getType + " does not exist in user lib class set.")
    else this.userLibraryClasses(l.getType) = l
  }
  
  /**
   * get containing set of given class
   */
  def getContainingSet(ar: JawaClass): Set[JawaClass] = {
    if(ar.isApplicationClass) getApplicationClasses
    else if(ar.isSystemLibraryClass) getSystemLibraryClasses
    else if(ar.isUserLibraryClass) getUserLibraryClasses
    else null
  }
  
  /**
   * remove given class from containing set
   */
  def removeFromContainingSet(ar: JawaClass) = {
    if(ar.isApplicationClass) removeApplicationClass(ar)
    else if(ar.isSystemLibraryClass) removeSystemLibraryClass(ar)
    else if(ar.isUserLibraryClass) removeUserLibraryClass(ar)
  }
  
  /**
   * retrieve the normal class hierarchy
   */
  def getClassHierarchy: ClassHierarchy ={
    this.hierarchy.build(this)
    this.hierarchy
  }
  
  /**
   * reset class hierarchy
   */
  def resetClassHierarchy() = this.hierarchy.reset()
  
  /**
   * add class into Global
   */
  def addClass(ar: JawaClass) = {
    if(containsClass(ar.getType) && getClazz(ar.typ).get.getResolvingLevel >= ar.getResolvingLevel) 
      reporter.error(TITLE, "duplicate class: " + ar.getName)
    else {
      addClassInternal(ar)
      modifyHierarchy
    }
  }
  
  protected[jawa] def addClassInternal(ar: JawaClass) = {
    getClazz(ar.typ) match {
      case Some(c) =>
        if(c.getResolvingLevel >= ar.getResolvingLevel) 
          reporter.warning(TITLE, "duplicate class: " + ar.getName)
      case None =>
        this.classes(ar.getType) = ar
        if(ar.isArray){
          ar.setSystemLibraryClass()
        } else if (containsClassFile(ar.getType)){
          getClassCategoryFromClassPath(ar.getType) match {
            case ClassCategory.APPLICATION => ar.setApplicationClass()
            case ClassCategory.USER_LIBRARY => ar.setUserLibraryClass()
            case ClassCategory.SYSTEM_LIBRARY => ar.setSystemLibraryClass()
          }
        } else {
          ar.setSystemLibraryClass()
        }
    }
  }
  
  /**
   * remove class from Global
   */
  def removeClass(typ: JawaType): Unit = {
    if(containsClass(typ)) {
      this.classes -= typ
      if(isSystemLibraryClasses(typ)) this.systemLibraryClasses -= typ
      else if(isUserLibraryClasses(typ)) this.userLibraryClasses -= typ
      else if(isApplicationClasses(typ)) this.applicationClasses -= typ
      modifyHierarchy
    }
  }
  
  protected def modifyHierarchy = {
    this.hierarchy.build(this)
  }
  
  /**
   * current Global contains the given class or not
   */
  def containsClass(typ: JawaType) = this.classes.contains(typ)
  
  /**
   * grab field from Global. Input example is java.lang.Throwable.stackState
   */
  def getField(fieldFQN: FieldFQN): Option[JawaField] = {
    try{
      val rType = fieldFQN.owner
      val fName = fieldFQN.fieldName
      getClazz(rType) match {
        case Some(c) => c.getField(fName, fieldFQN.typ)
        case None => None
      }
    } catch {
      case t: Throwable => None
    }
  }
  
  /**
   * return true if contains the given field. Input example is java.lang.Throwable.stackState
   */
  def containsField(fieldFQN: FieldFQN): Boolean = getField(fieldFQN).isDefined
  
  /**
   * get procedure from Global. Input example is Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getMethod(signature: Signature): Option[JawaMethod] = {
    Option(methodCache.getIfPresent(signature)) match {
      case a @ Some(m) => a
      case None =>
        val rType = signature.getClassType
        val subSig = signature.getSubSignature
        getClazz(rType) match {
          case Some(c) => 
            val m = c.getMethod(subSig)
            if(m.isDefined) methodCache.put(signature, m.get)
            m
          case None => None
        }
    }
  }
  
  def getMethodOrResolve(signature: Signature): Option[JawaMethod] = {
    Option(methodCache.getIfPresent(signature)) match {
      case a @ Some(m) => a
      case None =>
        val rType = signature.getClassType
        val subSig = signature.getSubSignature
        val c = getClassOrResolve(rType)
        val m = c.getMethod(subSig)
        if(m.isDefined) methodCache.put(signature, m.get)
        m
    }
  }
  
  /**
   * return true if contains the given procedure. Input example is Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def containsMethod(signature: Signature): Boolean = getMethod(signature).isDefined
  
  /**
   * get entry points
   */
  def getEntryPoints(entryMethodName: String): ISet[JawaMethod] = {
    findEntryPoints(entryMethodName)
  }
  
  /**
   * find entry points from current app/test cases
   */
  def findEntryPoints(entryMethodName: String): ISet[JawaMethod] = {
    val ep: MSet[JawaMethod] = msetEmpty
    getApplicationClasses.foreach{
      appRec =>
        if(appRec.declaresMethodByName(entryMethodName))
          appRec.getDeclaredMethodByName(entryMethodName) foreach{ep += _}
    }
    ep.toSet
  }
  
  def printDetails() = {
    println("***************Global***************")
    println("applicationClasses: " + getApplicationClasses)
    println("userLibraryClasses: " + getUserLibraryClasses)
    println("systemLibraryClasses: " + getSystemLibraryClasses)
    println("noCategorizedClasses: " + (getClasses -- getSystemLibraryClasses -- getUserLibraryClasses -- getApplicationClasses))
    println("hierarchy: " + getClassHierarchy)
    if(false){
      getClasses.foreach{
        case r=>
          r.printDetail()
          r.getDeclaredFields.foreach(_.printDetail())
          r.getDeclaredMethods.foreach(_.printDetail())
      }
      getClassHierarchy.printDetails()
    }
    println("******************************")
  }
  
  
  /**
   * didn't resolve this extends-relation list. It's a set of record names.
   */
  private val needToResolveExtends: MMap[JawaClass, MSet[JawaType]] = mmapEmpty
  
  /**
   * didn't resolve this outer class name. 
   */
  private val needToResolveOuterClass: MMap[JawaClass, JawaType] = mmapEmpty

  private val classesNeedUpdateInHierarchy: MSet[JawaClass] = msetEmpty
  
  /**
   * set of class names which not found in current environment
   */
  private val classNotFound: MSet[JawaType] = msetEmpty
  
  /**
   * dirty flag to indicate whether the manager is clean
   */
  private var dirty: Boolean = false
  
  def isDirty: Boolean = this.dirty
  
  def addNeedToResolveOuterClass(innerclass: JawaClass, outerType: JawaType) = {
    this.dirty = true
    needToResolveOuterClass(innerclass) = outerType
  }
  
  def addNeedToResolveExtend(childClass: JawaClass, parent: JawaType) = {
    this.dirty = true
    needToResolveExtends.getOrElseUpdate(childClass, msetEmpty) += parent
  }
  
  def addNeedToResolveExtends(childClass: JawaClass, parents: ISet[JawaType]) = {
    this.dirty = true
    needToResolveExtends.getOrElseUpdate(childClass, msetEmpty) ++= parents
  }
  
  def addClassesNeedUpdateInHierarchy(clazz: JawaClass) = this.classesNeedUpdateInHierarchy += clazz
  def getClassesNeedUpdateInHierarchy: ISet[JawaClass] = this.classesNeedUpdateInHierarchy.toSet
  def clearClassesNeedUpdateInHierarchy() = this.classesNeedUpdateInHierarchy.clear()
  
  def addClassNotFound(typ: JawaType) = this.classNotFound += typ
  def getClassNotFound: ISet[JawaType] = this.classNotFound.toSet
  
  /**
   * resolve classes relation of the whole program
   */
  protected[jawa] def resolveClassesRelationWholeProgram(): Any = {
    if(!isDirty) return
    val worklist: MList[JawaClass] = mlistEmpty
    worklist ++= needToResolveExtends.keySet ++ needToResolveOuterClass.keySet
    while(worklist.nonEmpty) {
      val clazz = worklist.remove(0)
      addClassesNeedUpdateInHierarchy(clazz)
      this.needToResolveOuterClass.get(clazz) match{
        case Some(o) =>
          getClazz(o) match{
            case Some(outer) =>
              this.needToResolveOuterClass -= clazz
              clazz.setOuterClass(outer)
            case None =>
              getMyClass(o) match {
                case Some(mc) =>
                  this.needToResolveOuterClass -= clazz
                  val outer = resolveFromMyClass(mc)
                  clazz.setOuterClass(outer)
                case None =>
                  this.needToResolveOuterClass -= clazz
                  val unknownOut = resolveToHierarchy(o)
                  clazz.setOuterClass(unknownOut)
              }
          }
        case None =>
      }
      this.needToResolveExtends.getOrElse(clazz, msetEmpty).foreach{
        parType =>
          getClazz(parType) match{
            case Some(parent) =>
              this.needToResolveExtends -= clazz
              if(parent.isInterface) clazz.addInterface(parent)
              else clazz.setSuperClass(parent)
            case None =>
              getMyClass(parType) match {
                case Some(mc) =>
                  this.needToResolveExtends -= clazz
                  val parent = resolveFromMyClass(mc)
                  if(parent.isInterface) clazz.addInterface(parent)
                  else clazz.setSuperClass(parent)
                case None =>
                  this.needToResolveExtends -= clazz
                  val unknownSu = resolveToHierarchy(parType)
                  clazz.setSuperClass(unknownSu)
              }
          }
      }
      this.needToResolveExtends -= clazz
      this.needToResolveOuterClass -= clazz
      worklist ++= needToResolveExtends.keySet ++ needToResolveOuterClass.keySet
    }
      
    getClasses.foreach {
      rec =>
        if(!rec.hasSuperClass && rec.getName != JAVA_TOPLEVEL_OBJECT){
          val obj = getClassOrResolveWithoutCache(JAVA_TOPLEVEL_OBJECT_TYPE)
          rec.setSuperClass(obj)
        }
    }
    this.dirty = !checkClassLoadingStatus
    if(isDirty) throw new RuntimeException("Class loading must have problem, since it should already finish.")
  }
  
  def checkClassLoadingStatus: Boolean = {
    this.needToResolveExtends.isEmpty && this.needToResolveOuterClass.isEmpty
  }
}
