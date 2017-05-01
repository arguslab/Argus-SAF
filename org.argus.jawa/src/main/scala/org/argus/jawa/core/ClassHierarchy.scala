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

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class ClassHierarchy(reporter: Reporter) extends JavaKnowledge {
  private final val TITLE = "ClassHierarchy"
  /**
   * this map is from class to it's sub-classes.
   */
  protected val classToSubClasses: MMap[JawaType, MSet[JawaType]] = mmapEmpty
  
  /**
   * this map is from interface to sub-interfaces.
   */
  protected val interfaceToSubInterfaces: MMap[JawaType, MSet[JawaType]] = mmapEmpty
  
  /**
   * this map is from class to all sub-classes.  Not filled in inside the build()
   */
  protected val classToAllSubClasses: MMap[JawaType, MSet[JawaType]] = mmapEmpty
  
  /**
   * this map is from interface to all sub-interfaces. Not filled in inside the build()
   */
  protected val interfaceToAllSubInterfaces: MMap[JawaType, MSet[JawaType]] = mmapEmpty
  
  /**
   * this map is from interface to direct implementers
   */
  protected val interfaceToImplementers: MMap[JawaType, MSet[JawaType]] = mmapEmpty

  protected val classToSuperClass: MMap[JawaType, JawaType] = mmapEmpty

  protected val resolvedTypes: MSet[JawaType] = msetEmpty

  def resolved(typ: JawaType): Boolean = resolvedTypes.contains(typ)

  /**
   * construct a hierarchy from the current scene i.e. Global
   */
  def build(global: Global): ClassHierarchy = {
    val allClasses = global.getClassesNeedUpdateInHierarchy
    allClasses.foreach {
      clazz =>
        resolvedTypes += clazz.getType
        if(clazz.hasSuperClass){
          classToSuperClass(clazz.getType) = clazz.getSuperClass
          if(clazz.isInterface){
            clazz.getInterfaces.foreach{i => this.interfaceToSubInterfaces.getOrElseUpdate(i, msetEmpty) += clazz.getType}
          } else {
            this.classToSubClasses.getOrElseUpdate(clazz.getSuperClass, msetEmpty) += clazz.getType
            clazz.getInterfaces.foreach{i => this.interfaceToImplementers.getOrElseUpdate(i, msetEmpty) += clazz.getType}
          }
        }
    }
    // fill in the implementers sets with subclasses
    allClasses.foreach {
      clazz =>
        if(clazz.isInterface){
          val imps = this.interfaceToImplementers.getOrElseUpdate(clazz.getType, msetEmpty)
          imps ++= imps.map(getAllSubClassesOfIncluding).fold(isetEmpty)(_ ++ _)
        }
    }
    global.clearClassesNeedUpdateInHierarchy()
    this
  }

  /**
   * return a set of all sub-classes of r, including itself
   */
  def getAllSubClassesOfIncluding(r: JawaType): ISet[JawaType] = {
    getAllSubClassesOf(r) + r
  }

  /**
   * return a set of all sub-classes of r
   */
  def getAllSubClassesOf(r: JawaType): ISet[JawaType] = {
    this.classToAllSubClasses.get(r) match{
      case Some(classes) => classes.toSet //if already cached return the value
      case None =>
        val subClasses = this.classToSubClasses.getOrElseUpdate(r, msetEmpty)
        if(subClasses.nonEmpty){
          val allSubClasses = subClasses.map{getAllSubClassesOfIncluding}.reduce((s1, s2) => s1 ++ s2)
          this.classToAllSubClasses.getOrElseUpdate(r, msetEmpty) ++= allSubClasses
          allSubClasses
        } else isetEmpty
    }
  }

  /**
   * return a set of all super-classes of r, including itself
   */
  def getAllSuperClassesOfIncluding(r: JawaType): ISet[JawaType] = {
    getAllSuperClassesOf(r) + r
  }

  /**
   * return a set of all super-classes of r
   */
  def getAllSuperClassesOf(r: JawaType): ISet[JawaType] = {
    var rl = r
    val l: MSet[JawaType] = msetEmpty
    while(classToSuperClass.contains(rl)){
      rl = classToSuperClass(rl)
      l += rl
    }
    l.toSet
  }

  /**
   * return a set of all sub-interfaces of r, including itself
   */
  def getAllSubInterfacesOfIncluding(r: JawaType): ISet[JawaType] = {
    getAllSubInterfacesOf(r) + r
  }

  /**
   * return a set of all sub-interfaces of r
   */
  def getAllSubInterfacesOf(r: JawaType): ISet[JawaType] = {
    this.interfaceToAllSubInterfaces.get(r) match{
      case Some(classes) => classes.toSet //if already cached return the value
      case None =>
        val subClasses = this.interfaceToSubInterfaces.getOrElseUpdate(r, msetEmpty)
        if(subClasses.nonEmpty){
          val allSubClasses = subClasses.map{getAllSubInterfacesOfIncluding}.reduce((s1, s2) => s1 ++ s2)
          this.interfaceToAllSubInterfaces.getOrElseUpdate(r, msetEmpty) ++= allSubClasses
          allSubClasses
        } else isetEmpty
    }
  }

  /**
   * return a set of sub-classes of r, including itself
   */
  def getSubClassesOfIncluding(r: JawaType): ISet[JawaType] = {
    getSubClassesOf(r) + r
  }

  /**
   * return a set of sub-classes of r
   */
  def getSubClassesOf(r: JawaType): ISet[JawaType] = {
    this.classToSubClasses.getOrElse(r, msetEmpty).toSet
  }

  /**
   * return super-classes of r
   */
  def getSuperClassOf(r: JawaType): Option[JawaType] = classToSuperClass.get(r)

  /**
   * return a set of sub-interfaces of r, including itself
   */
  def getSubInterfacesOfIncluding(r: JawaType): ISet[JawaType] = {
    getSubInterfacesOf(r) + r
  }

  /**
   * return a set of sub-interfaces of r
   */
  def getSubInterfacesOf(r: JawaType): ISet[JawaType] = {
    this.interfaceToSubInterfaces.getOrElse(r, msetEmpty).toSet
  }

  /**
   * get all implementers of r
   */
  def getAllImplementersOf(r: JawaType): ISet[JawaType] = {
    val subI = getSubInterfacesOfIncluding(r)
    subI.map(getImplementersOf).fold(isetEmpty)(_ ++ _)
  }

  /**
   * get implementers of r
   */
  def getImplementersOf(r: JawaType): ISet[JawaType] = {
    this.interfaceToImplementers.getOrElse(r, msetEmpty).toSet
  }

  /**
   * return true if child is a subclass of given parent recursively
   */
  def isClassRecursivelySubClassOf(child: JawaType, parent: JawaType): Boolean = {
    getAllSuperClassesOf(child).contains(parent)
  }

   /**
   * return true if child is a subclass of given parent recursively
   */
  def isClassRecursivelySubClassOfIncluding(child: JawaType, parent: JawaType): Boolean = {
    getAllSuperClassesOfIncluding(child).contains(parent)
  }

  /**
   * return true if child is a subclass of given parent
   */
  def isClassSubClassOf(child: JawaType, parent: JawaType): Boolean = getSuperClassOf(child).orNull == parent

  /**
   * return true if child is a super class of given parent recursively
   */
  def isClassRecursivelySuperClassOf(parent: JawaType, child: JawaType): Boolean = {
    getAllSubClassesOf(parent).contains(child)
  }

  /**
   * return true if child is a super class of given parent recursively
   */
  def isClassRecursivelySuperClassOfIncluding(parent: JawaType, child: JawaType): Boolean = {
    getAllSubClassesOfIncluding(parent).contains(child)
  }

  /**
   * return true if child is a subclass of given parent
   */
  def isClassSuperClassOf(parent: JawaType, child: JawaType): Boolean = {
    classToSuperClass.get(child).orNull == parent
  }

  /**
   * return true if child is a subinterface of given parent recursively
   */
  def isClassRecursivelySubInterfaceOf(child: JawaType, parent: JawaType): Boolean = {
    interfaceToAllSubInterfaces(parent).contains(child)
  }

   /**
   * return true if child is a subinterface of given parent recursively
   */
  def isClassRecursivelySubInterfaceOfIncluding(child: JawaType, parent: JawaType): Boolean = {
    parent == child || isClassRecursivelySubInterfaceOf(child, parent)
  }

  /**
   * return true if child is a subinterface of given parent
   */
//  def isClassSubInterfaceOf(child: JawaType, parent: JawaType): Boolean = {
//    getSuperInterfacesOf(child).contains(parent)
//  }

  /**
   * return true if the procedure is visible from type from
   */
  def isMethodVisible(from: JawaType, method: JawaMethod): Boolean = {
    if(method.isUnknown) true
    else if(method.isPublic) true
    else if(method.isPrivate) method.getDeclaringClass.getType == from
    else if(method.isProtected) isClassRecursivelySubClassOfIncluding(from, method.getDeclaringClass.getType)
    /* If none of these access control access flag been set, means the method has default or package level access
     * which means this method can be accessed within the class or other classes in the same package.
     */
    else method.getDeclaringClass.getType == from || method.getDeclaringClass.getPackage == from.getPackage
  }

  /**
   * Given an object created by o = new R as type R, return the procedure which will be called by o.p()
   */
  def resolveConcreteDispatch(concreteType: JawaClass, p: JawaMethod): Option[JawaMethod] = {
    if(concreteType.isInterface){
      reporter.warning(TITLE, "concreteType need to be class type: " + concreteType)
      None
    } else {
      val pSubSig = p.getSubSignature
      resolveConcreteDispatch(concreteType, pSubSig)
    }
  }

  /**
   * Given an object created by o = new R as type R, return the procedure which will be called by o.p()
   */
  def resolveConcreteDispatch(concreteType: JawaClass, pSubSig: String): Option[JawaMethod] = {
    if(concreteType.isInterface){
      reporter.warning(TITLE, "concreteType need to be class type: " + concreteType)
      None
    } else {
      findMethodThroughHierarchy(concreteType, pSubSig) match {
        case apOpt @ Some(ap) =>
          if(ap.isAbstract){
            reporter.warning(TITLE, "Target procedure needs to be non-abstract method type: " + ap)
            None
          }
          else if(!isMethodVisible(concreteType.getType, ap)){
            reporter.warning(TITLE, "Target procedure " + ap + " needs to be visible from: " + concreteType)
            None
          }
          else apOpt
        case None =>
          reporter.warning(TITLE, "Cannot resolve concrete dispatch!\n" + "Type:" + concreteType + "\nMethod:" + pSubSig)
          None
      }
    }
  }

  private def findMethodThroughHierarchy(clazz: JawaClass, subSig: String): Option[JawaMethod] = {
    if(clazz.isUnknown){
      this.synchronized{
        clazz.getMethod(subSig) match{
          case Some(p) => Some(p)
          case None =>
            val unknownSig = generateSignatureFromOwnerAndMethodSubSignature(clazz, subSig)
            val unknownMethod = generateUnknownJawaMethod(clazz, unknownSig)
            Some(unknownMethod)
        }
      }
    } else {
    clazz.getMethod(subSig) match{
      case Some(p) =>
        Some(p)
      case None =>
        if(clazz.hasSuperClass) findMethodThroughHierarchy(clazz.global.getClassOrResolve(clazz.getSuperClass), subSig)
        else None
    }
    }
  }

  /**
   * Given an abstract dispatch to an object of type r and a subsig p, gives a list of possible receiver's methods
   */
  def resolveAbstractDispatch(r: JawaClass, pSubSig: String): ISet[JawaMethod] = {
    val results: MSet[JawaMethod] = msetEmpty
    val classes: MSet[JawaClass] = msetEmpty
    if(r.isInterface){
      classes ++= getAllImplementersOf(r.getType).map(r.global.getClassOrResolve)
    } else {
      classes ++= getAllSubClassesOfIncluding(r.getType).map(r.global.getClassOrResolve)
    }

    classes.filter { r => !r.isAbstract }.foreach{
      rec =>
        findMethodThroughHierarchy(rec, pSubSig) match {
          case Some(p) => if(!p.isAbstract) results += p
          case None =>
        }
    }
    if(results.isEmpty){
      if(r.isInterface || r.isAbstract){
        findMethodThroughHierarchy(r, pSubSig) match { //check whether this method is in the java.lang.Object class.
          case Some(p) => if(!p.isAbstract) results += p
          case None => // It's an unknown method since we cannot find any implementer of this interface and such method is getting invoked.
        }
        if(results.isEmpty){
          val unknowntyp = r.getType.toUnknown
          val unknownrec = r.global.getClassOrResolve(unknowntyp)
          val unknownSig = generateSignatureFromOwnerAndMethodSubSignature(unknownrec, pSubSig)
          val unknownMethod = unknownrec.getMethod(pSubSig) match {
            case Some(m) => m
            case None => generateUnknownJawaMethod(unknownrec, unknownSig)
          }
          results += unknownMethod
        }
      } else {
        reporter.warning(TITLE, "Could not resolve abstract dispath for:\nclass:" + r + " method:" + pSubSig)
      }
    }
    results.toSet
  }

  /**
   * Given an abstract dispatch to an object of type r and a procedure p, gives a list of possible receiver's methods
   */
  def resolveAbstractDispatch(r: JawaClass, p: JawaMethod): Set[JawaMethod] = {
    val pSubSig = p.getSubSignature
    resolveAbstractDispatch(r, pSubSig)
  }

  def reset(): Unit = {
    this.classToAllSubClasses.clear()
    this.classToSubClasses.clear()
    this.interfaceToAllSubInterfaces.clear()
    this.interfaceToImplementers.clear()
    this.interfaceToSubInterfaces.clear()
    this.resolvedTypes.clear()
  }

  def printDetails(): Unit = {
    println("==================hierarchy==================")
    println("interfaceToSubInterfaces:\n" + this.interfaceToSubInterfaces)
    println("classToSubClasses:\n" + this.classToSubClasses)
    println("interfaceToImplementers:\n" + this.interfaceToImplementers)
    println("====================================")
  }

  override def toString: String = {
    val sb = new StringBuffer
    sb.append("\ninterface to sub-interfaces:\n")
    this.interfaceToSubInterfaces.foreach{
      case (k, v) =>
        sb.append(k + "->" + v + "\n")
    }
    sb.append("interface to implementers:\n")
    this.interfaceToImplementers.foreach{
      case (k, v) =>
        sb.append(k + "->" + v + "\n")
    }
    sb.append("class to sub-classes:\n")
    this.classToSubClasses.foreach{
      case (k, v) =>
        sb.append(k + "->" + v + "\n")
    }
    sb.toString.intern()
  }
}

case class MethodInvisibleException(detailMessage: String) extends RuntimeException
