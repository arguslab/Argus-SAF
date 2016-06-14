/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.util

import org.argus.jawa.core._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object CallHandler {
  /**
   * get callee procedure from Center. Input: .equals:(Ljava/lang/Object;)Z
   */
  //def getCalleeMethod(from: JawaClass, pSubSig: String): JawaMethod = {
  //  Center.getClassHierarchy.resolveConcreteDispatch(from, pSubSig) match{
  //    case Some(ap) => ap
  //    case None => Center.getMethodWithoutFailing(Center.UNKNOWN_PROCEDURE_SIG)
  //  }
  //}

  /**
   * check and get virtual callee procedure from Center. Input: equals:(Ljava/lang/Object;)Z
   */
  def getVirtualCalleeMethod(global: Global, fromType: JawaType, pSubSig: String): Option[JawaMethod] = {
    val typ =
      if(fromType.isArray) JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE  // any array in java is an Object, so primitive type array is an object, object's method can be called
      else fromType
    val from = global.getClassOrResolve(typ)
    global.getClassHierarchy.resolveConcreteDispatch(from, pSubSig)
  }
  
  /**
   * check and get virtual callee procedure from Center. Input: equals:(Ljava/lang/Object;)Z
   */
  def getUnknownVirtualCalleeMethods(global: Global, baseType: JawaType, pSubSig: String): ISet[JawaMethod] = {
    val typ =
      if(baseType.isArray) JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE  // any array in java is an Object, so primitive type array is an object, object's method can be called
      else baseType.removeUnknown()
    val baseRec = global.getClassOrResolve(typ)
    val methods = global.getClassHierarchy.resolveAbstractDispatch(baseRec, pSubSig)
    val m = methods.filter(m => m.isConcrete && !m.isStatic)
    if(m.isEmpty) methods.filter(m => !m.isStatic)
    else m
  }

  /**
   * check and get super callee procedure from Center. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getSuperCalleeMethod(global: Global, pSig: Signature): Option[JawaMethod] = {
    val fromType = pSig.getClassType
    val pSubSig = pSig.getSubSignature
    val from = global.getClassOrResolve(fromType)
    global.getClassHierarchy.resolveConcreteDispatch(from, pSubSig)
  }

  /**
   * check and get static callee procedure from Center. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getStaticCalleeMethod(global: Global, procSig: Signature): Option[JawaMethod] = {
    val recType = procSig.getClassType
    val pSubSig = procSig.getSubSignature
    val from = global.getClassOrResolve(recType)
    if(from.isUnknown) {
      this.synchronized{
        global.getMethod(procSig) match {
          case None => 
            Some(global.generateUnknownJawaMethod(from, procSig))
          case a => a
        }
      }
    } else {
      global.getClassHierarchy.resolveConcreteDispatch(from, pSubSig)
    }
  }

  /**
   * check and get direct callee procedure from Center. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getDirectCalleeMethod(global: Global, procSig: Signature): Option[JawaMethod] = {
    val pSubSig = procSig.getSubSignature
    val recType = procSig.getClassType
    val rec = global.getClassOrResolve(recType)
    if(rec.isUnknown){
      this.synchronized{
        global.getMethod(procSig) match {
          case None => 
            Some(global.generateUnknownJawaMethod(rec, procSig))
          case a => a
        }
      }
    } else {
      rec.getMethod(pSubSig)
    }
  }

  def resolveSignatureBasedCall(global: Global, callSig: Signature, typ: String): ISet[JawaMethod] = {
    val result: MSet[JawaMethod] = msetEmpty
    val classType = callSig.getClassType
    val subSig = callSig.getSubSignature
    val rec = global.getClassOrResolve(classType)
    if(!rec.isUnknown){
      typ match{
        case "interface" =>
          require(rec.isInterface)
          global.getClassHierarchy.getAllImplementersOf(rec).foreach{
            record =>
              if(record.isConcrete){
                val fromType = record.getType
                var callee: Option[JawaMethod] = None 
                try{
                  callee = getVirtualCalleeMethod(global, fromType, subSig)
                } catch {
                  case pe: MethodInvisibleException =>
                    println(pe.getMessage)
                  case a: Throwable =>
                    throw a
                }
                if(callee.isDefined)
                  result += callee.get
              }
          }
        case "virtual" =>
          require(!rec.isInterface)
          global.getClassHierarchy.getAllSubClassesOfIncluding(rec).foreach{
            record =>
              if(record.isConcrete){
                val fromType = record.getType
                var callee: Option[JawaMethod] = None 
                try{
                  callee = getVirtualCalleeMethod(global, fromType, subSig)
                } catch {
                  case pe: MethodInvisibleException =>
                    println(pe.getMessage)
                  case a: Throwable =>
                    throw a
                }
                if(callee.isDefined)
                  result += callee.get
              }
          }
        case "super" =>
          result ++= getSuperCalleeMethod(global, callSig)
        case "direct" =>
          result ++= getDirectCalleeMethod(global, callSig)
        case "static" =>
          result ++= getStaticCalleeMethod(global, callSig)
      }
    }
    result.toSet
  }
}
