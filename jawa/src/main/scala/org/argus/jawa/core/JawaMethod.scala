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

import org.argus.jawa.core.ast.MethodDeclaration
import org.argus.jawa.core.elements._
import org.argus.jawa.core.util._

/**
 * This class is an jawa representation of a jawa method. It can belong to JawaClass.
 * You can also construct it manually.
 *
 * @constructor create a jawa method
 * @param declaringClass The declaring class of this method
 * @param name name of the method. e.g. stackState
 * @param thisOpt this param of the method, if the method is static or native it is None
 * @param params List of param name with its type of the method
 * @param returnType return type of the method
 * @param accessFlags access flags of this field
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class JawaMethod(declaringClass: JawaClass,
    name: String,
    thisOpt: Option[String],
    params: ISeq[(String, JawaType)],
    returnType: JawaType,
    accessFlags: Int) extends JawaElement with JavaKnowledge {

  final val TITLE = "JawaMethod"
  var DEBUG: Boolean = false

  require(this.declaringClass != null &&
          this.name != null &&
          this.thisOpt != null &&
          this.params != null &&
          this.returnType != null &&
          this.accessFlags >= 0) // NON-NIL

  require(!this.name.isEmpty)
  require((isStatic || isNative || isAbstract) || this.thisOpt.isDefined, getName + " not has this.")

  private val signature: Signature = {
    val dc = this.getDeclaringClass
    val proto = generateProto(this)
    new Signature(dc.getType, this.getName, proto)
  }

  /**
    * generate sub-signature of this method
    */
  private def generateProto(method: JawaMethod): String = {
    val sb: StringBuffer = new StringBuffer
    val rt = method.getReturnType
    val pts = method.getParamTypes
    sb.append("(")
    for(i <- pts.indices){
      val pt = pts(i)
      sb.append(method.formatTypeToSignature(pt))
    }
    sb.append(")")
    sb.append(method.formatTypeToSignature(rt))
    sb.toString.intern()
  }

  def getDeclaringClass: JawaClass = this.declaringClass

  getDeclaringClass.addMethod(this)

  /**
   * name of the method. e.g. equals
   */
  def getName: String = name

  /**
   * display this method. e.g. isInteresting(IClassFile)
   */
  def getDisplay: String = {
    val sb = new StringBuilder
    sb.append(getName)
    sb.append("(")
    var i = 0
    getParamTypes foreach {
      tpe =>
        if(i == 0){
          sb.append(tpe.simpleName)
        } else {sb.append(", " + tpe.simpleName)}
        i += 1
    }
    sb.append("): ")
    sb.append(getReturnType.simpleName)
    sb.toString().intern()
  }

  def getFullName: String = getDeclaringClass.getType.name + "." + getName

  /**
   * signature of the method. e.g. Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getSignature: Signature = this.signature

  /**
   * sub-signature of the method. e.g. equals:(Ljava/lang/Object;)Z
   */
  def getSubSignature: String = {
    getSignature.getSubSignature
  }

  def getThisName: String = {
    require(!isStatic && !isNative)
    this.thisOpt.get
  }

  def getThisType: JawaType = {
    require(!isStatic && !isNative)
    getDeclaringClass.getType
  }

  /**
   * list of parameters. e.g. List((v1, java.lang.Object), (v2, java.lang.String))
   */
  def getParams: ISeq[(String, JawaType)] = this.params

  /**
   * list of parameter types. e.g. List(java.lang.Object, java.lang.String)
   */
  def getParamTypes: ISeq[JawaType] = getParams.map(_._2)

  /**
   * list of parameter names
   */
  def getParamNames: ISeq[String] = getParams.map(_._1)

  /**
   * get i'th parameter of this method
   */
  def getParam(i: Int): (String, JawaType) = getParams(i)

  /**
   * get i'th parameter's type of this method
   */
  def getParamType(i: Int): JawaType = getParamTypes(i)

  /**
   * get i'th parameter's name of this method
   */
  def getParamName(i: Int): String = getParamNames(i)

  /**
   * return type. e.g. boolean
   */
  def getReturnType: JawaType = this.returnType

  def matches(name: String, argTypes: IList[JawaType]): Boolean = {
    var result = true
    if (getParamTypes.size == argTypes.size) {
      if(getParamTypes != argTypes) {
        for (i <- getParamTypes.indices) {
          val pType = getParamType(i)
          val aType = argTypes(i)
          if(pType.isPrimitive || aType.isPrimitive) {
            if(pType != aType) {
              result = false
            }
          } else {
            val pClass = getDeclaringClass.global.getClassOrResolve(pType)
            val aClass = getDeclaringClass.global.getClassOrResolve(aType)
            if (!getDeclaringClass.global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(aClass, pClass)) {
              result = false
            }
          }
        }
      }
    } else {
      result = false
    }
    result
  }

  /**
   * exceptions thrown by this method
   */
  private[jawa] val thrownExceptions: MSet[JawaClass] = msetEmpty

  /**
   * Data structure to store all information about a catch clause
   * LocUri should always looks like "L?[0-9a-f]+"
   */
  case class ExceptionHandler(exception: JawaClass, fromTarget: String, toTarget: String, jumpTo: String){
    def handleException(exc: JawaClass, locUri: String): Boolean = {
      (exception == exc || exception.isChildOf(exc.getType)) && withInScope(locUri)
    }
    def withInScope(locUri: String): Boolean = {
      getLocation(fromTarget) <= getLocation(locUri) && getLocation(locUri) <= getLocation(toTarget)
    }
    def getLocation(locUri: String): Int = {
      val loc = locUri.substring(locUri.lastIndexOf("L") + 1)
      Integer.getInteger(loc, 16)
    }
  }

  /**
   * exception handlers
   */
  private[jawa] val exceptionHandlers: MList[ExceptionHandler] = mlistEmpty

  /**
   * retrieve code belong to this method
   */
  def retrieveCode: Option[String] = try{Some(getBody.toCode)} catch {case _: Exception => None}

  private var md: Option[MethodDeclaration] = None

  def setBody(md: MethodDeclaration): Unit = {
    this.md = Some(md)
  }

  /**
   * get MethodDeclaration
   */
  def getBody: MethodDeclaration = {
    if(isUnknown) throw new RuntimeException(getSignature + " is an unknown method.")
    if(getDeclaringClass.isSystemLibraryClass) throw new RuntimeException(getSignature + " is an system library method.")
    this.md.get
  }

  /**
   * Adds exception which can be thrown by this method
   */
  def addExceptionIfAbsent(exc: JawaClass): Any = {
    if(!throwException(exc)) addException(exc)
  }

  /**
   * Adds exception thrown by this method
   */
  def addException(exc: JawaClass): thrownExceptions.type = {
    if(DEBUG) println("Adding Exception: " + exc)
    if(throwException(exc)) throw new RuntimeException("already throwing exception: " + exc)
    this.thrownExceptions += exc
  }

  /**
   * set exception with details
   */
  def addExceptionHandler(excName: String, fromTarget: String, toTarget: String, jumpTo: String): exceptionHandlers.type = {
    val recType: JawaType = getTypeFromJawaName(excName)
    val exc: JawaClass = getDeclaringClass.global.getClazz(recType) match {
      case Some(c) => c
      case None =>
        JawaClass(getDeclaringClass.global, recType, 0)
    }
    val handler = ExceptionHandler(exc, fromTarget, toTarget, jumpTo)
    if(DEBUG) println("Adding Exception Handler: " + handler)
    if(this.exceptionHandlers.contains(handler)) throw new RuntimeException("already have exception handler: " + handler)
    addExceptionIfAbsent(exc)
    this.exceptionHandlers += handler
  }

  /**
   * removes exception from this method
   */
  def removeException(exc: JawaClass): exceptionHandlers.type = {
    if(DEBUG) println("Removing Exception: " + exc)
    if(!throwException(exc)) throw new RuntimeException("does not throw exception: " + exc)
    this.thrownExceptions -= exc
    this.exceptionHandlers --= this.exceptionHandlers.filter(_.exception != exc)
  }

  /**
   * throws this exception or not?
   */
  def throwException(exc: JawaClass): Boolean = this.thrownExceptions.contains(exc)

  /**
   * get thrown exception target location
   */
  def getThrownExcetpionTarget(exc: JawaClass, locUri: String): Option[String] = {
    this.exceptionHandlers.find(_.handleException(exc, locUri)).map(_.jumpTo)
  }

  /**
   * set exceptions for this method
   */
  def setExceptions(excs: Set[JawaClass]): thrownExceptions.type = {
    this.thrownExceptions.clear()
    this.thrownExceptions ++= excs
  }

  /**
   * get exceptions
   */
  def getExceptions: ISet[JawaClass] = this.thrownExceptions.toSet

  /**
   * return true if this method is concrete which means it is not abstract nor native nor unknown
   */
  def isConcrete: Boolean = !isAbstract && !isNative && !isUnknown

  /**
   * return true if this method is synthetic
   */
  def isSynthetic: Boolean = AccessFlag.isSynthetic(this.accessFlags)

  /**
   * return true if this method is constructor
   */
  def isConstructor: Boolean = AccessFlag.isConstructor(this.accessFlags)

  /**
   * return true if this method is declared_synchronized
   */
  def isDeclaredSynchronized: Boolean = AccessFlag.isDeclaredSynchronized(this.accessFlags)

  private var implements: Option[JawaMethod] = None

  private var overrides: Option[JawaMethod] = None

  private def setImplementsOrOverrides(m: JawaMethod): Unit = {
    if(m.isAbstract) this.implements = Some(m)
    else this.overrides = Some(m)
  }

  def getImplements: Option[JawaMethod] = {
    if(this.implements.isDefined) this.implements
    else {
      computeImplementsOrOverrides(getDeclaringClass)
      this.implements
    }
  }

  def getOverrides: Option[JawaMethod] = {
    if(this.overrides.isDefined) this.overrides
    else {
      computeImplementsOrOverrides(getDeclaringClass)
      this.overrides
    }
  }

  private def computeImplementsOrOverrides(clazz: JawaClass): Unit = {
    clazz.getDeclaredMethods foreach {
      m =>
        if(m.getSubSignature == this.getSubSignature){
          setImplementsOrOverrides(m)
          return
        }
    }
    if(clazz.hasSuperClass) computeImplementsOrOverrides(clazz.getSuperClass)
  }

  def isImplements: Boolean = {
    getImplements.isDefined
  }

  def isOverride: Boolean = getOverrides.isDefined

  /**
   * return true if this method is main method
   */
  def isMain: Boolean = isPublic && isStatic && getSubSignature == "main:([Ljava/lang/string;)V"

  /**
   * return true if this method is a class initializer or main function
   */
  def isEntryMethod: Boolean = {
    if(isStatic && name == getDeclaringClass.staticInitializerName) true
    else isMain
  }

  def printDetail(): Unit = {
    println("--------------AmandroidMethod--------------")
    println("name: " + getName)
    println("signature: " + getSignature)
    println("subSignature: " + getSubSignature)
    println("declaringClass: " + getDeclaringClass)
    println("paramTypes: " + getParamTypes)
    println("accessFlags: " + getAccessFlagsStr)
    println("----------------------------")
  }

  override def toString: String = getSignature.toString

}
