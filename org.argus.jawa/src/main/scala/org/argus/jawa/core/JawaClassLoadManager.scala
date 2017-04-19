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
import com.google.common.cache.CacheBuilder
import com.google.common.cache.Cache
import org.argus.jawa.core.io.SourceFile

trait JawaClassLoadManager extends JavaKnowledge with JawaResolver { self: Global =>

  /**
   * class hierarchy of all classes in the current Global
   */
  protected val hierarchy: ClassHierarchy = new ClassHierarchy(reporter)

  /**
   * get all the application classes
   */
  def getApplicationClasses: ISet[JawaClass] = resolveAllClasses(this.applicationClassCodes)
  
  /**
   * get all the third party lib classes
   */
  def getUserLibraryClasses: ISet[JawaClass] = resolveAllClasses(this.userLibraryClassCodes)
  
  /**
   * get all the application classes
   */
  def isApplicationClasses(typ: JawaType): Boolean = this.applicationClassCodes.contains(typ)
  
  /**
   * get all the system library classes
   */
  def isSystemLibraryClasses(typ: JawaType): Boolean = !isApplicationClasses(typ) && !isUserLibraryClasses(typ)
  
  /**
   * get all the third party lib classes
   */
  def isUserLibraryClasses(typ: JawaType): Boolean = this.userLibraryClassCodes.contains(typ)

  /**
   * Resolve all application classes to Hierarchy level. Be careful, it will take some time.
   */
  protected[core] def resolveAllClasses(codes: MMap[JawaType, SourceFile]): ISet[JawaClass] = {
    val result: MSet[JawaClass] = msetEmpty
    codes foreach {
      case (typ, _) =>
        if(!isJavaPrimitive(typ)) //TODO: Hack to avoid exception caused by rename class to java primitives obfuscation.
          result += getClassOrResolve(typ)
    }
    result.toSet
  }
  
  protected val classCache: Cache[JawaType, JawaClass] = CacheBuilder.newBuilder()
    .maximumSize(3000).build[JawaType, JawaClass]()
        
  protected val methodCache: Cache[Signature, JawaMethod] = CacheBuilder.newBuilder()
    .maximumSize(500).build[Signature, JawaMethod]()
  
  /**
   * get class by type; if it does not exist, return None
   */
  def getClazz(typ: JawaType): Option[JawaClass] = {
    Option(classCache.getIfPresent(typ)) match {
      case a @ Some(_) => a
      case None =>
        try {
          val c = resolveClass(typ, allowUnknown = false)
          classCache.put(typ, c)
          Some(c)
        }
        catch {
          case _: JawaResolverError => None
        }
    }
  }
  
  /**
   * get class by type, if not present resolve it.
   */
  def getClassOrResolve(typ: JawaType): JawaClass = {
    Option(classCache.getIfPresent(typ)) match {
      case Some(a) => a
      case None =>
        val c = resolveClass(typ, allowUnknown = true)
        classCache.put(typ, c)
        c
    }
  }

  /**
   * retrieve the class hierarchy
   */
  def getClassHierarchy: ClassHierarchy ={
    this.hierarchy.build(this)
    this.hierarchy
  }
  
  /**
    * reset class hierarchy
    */
  def resetClassHierarchy(): Unit = this.hierarchy.reset()

  /**
    * remove class from Global
    */
  def removeClass(typ: JawaType): Unit = {
    classCache.invalidate(typ)
//    modifyHierarchy
  }
  
  /**
   * current Global contains the given class or not
   */
  def containsClass(typ: JawaType): Boolean = containsClassFile(typ)
  
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
      case _: Throwable => None
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
      case a @ Some(_) => a
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
      case a @ Some(_) => a
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
  
  def printDetails(): Unit = {
    println("***************Global***************")
    println("applicationClasses: " + getApplicationClasses)
    println("userLibraryClasses: " + getUserLibraryClasses)
    println("hierarchy: " + getClassHierarchy)
    println("******************************")
  }

  private val classesNeedUpdateInHierarchy: MSet[JawaClass] = msetEmpty
  
  /**
   * set of class names which not found in current environment
   */
  private val classNotFound: MSet[JawaType] = msetEmpty
  
  protected[core] def addClassesNeedUpdateInHierarchy(clazz: JawaClass): Unit = this.classesNeedUpdateInHierarchy += clazz
  protected[core] def getClassesNeedUpdateInHierarchy: ISet[JawaClass] = this.classesNeedUpdateInHierarchy.toSet
  protected[core] def clearClassesNeedUpdateInHierarchy(): Unit = this.classesNeedUpdateInHierarchy.clear()

  protected[core] def addClassNotFound(typ: JawaType): Unit = this.classNotFound += typ
  protected[core] def getClassNotFound: ISet[JawaType] = this.classNotFound.toSet
}
