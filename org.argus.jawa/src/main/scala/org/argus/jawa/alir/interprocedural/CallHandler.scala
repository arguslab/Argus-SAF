/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.interprocedural

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.{Instance, PTAResult, VarSlot}
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object CallHandler {

  def getCalleeSet(global: Global, cs: CallStatement, sig: Signature, callerContext: Context, ptaResult: PTAResult): ISet[RFACallee] = {
    val subSig = sig.getSubSignature
    val typ = cs.kind
    val calleeSet = msetEmpty[RFACallee]
    typ match {
      case "virtual" | "interface" | "super" | "direct" =>
        val recv = VarSlot(cs.recvOpt.get)
        val recvValue: ISet[Instance] = ptaResult.pointsToSet(callerContext, recv)
        def handleUnknown(typ: JawaType) = try {
          val unknown = global.getClassOrResolve(typ)
          val unknown_base = global.getClassOrResolve(typ.removeUnknown())
          val c2 = global.getClassOrResolve(sig.classTyp)
          val actc = if(c2.isInterface || unknown_base.isChildOf(c2.getType)) unknown else c2
          calleeSet ++= actc.getMethod(subSig).map(m => UnknownCallee(m.getSignature))
        } catch {
          case _: Exception =>
        }
        val args = (cs.recvOpt ++ cs.args).toList
        // Try to resolve indirect call first.
        IndirectCallResolver.getCallResolver(global, sig.classTyp, subSig) match {
          case Some(c) =>
            c.getCallTarget(global, recvValue, callerContext, args, ptaResult) match { case (targets, mapFactsToCallee) =>
              calleeSet ++= targets.map{ case (m, ins) => IndirectInstanceCallee(m.getSignature, ins, mapFactsToCallee)}
            }
            if(calleeSet.isEmpty) {
              handleUnknown(sig.getClassType.toUnknown)
            }
          case None =>
            recvValue.foreach { ins =>
              if (typ == "super") {
                calleeSet ++= CallHandler.getSuperCalleeMethod(global, sig).map(m => InstanceCallee(m.getSignature, ins))
              } else if (typ == "direct") {
                calleeSet ++= CallHandler.getDirectCalleeMethod(global, sig).map(m => InstanceCallee(m.getSignature, ins))
              } else {
                if (ins.isUnknown) {
                  handleUnknown(ins.typ)
                } else {
                  CallHandler.getVirtualCalleeMethod(global, ins.typ, subSig).map(m => InstanceCallee(m.getSignature, ins)) match {
                    case Some(c) => calleeSet += c
                    case None =>
                      handleUnknown(ins.typ.toUnknown)
                  }
                }
              }
            }
            if(recvValue.isEmpty) {
              handleUnknown(sig.getClassType.toUnknown)
            }
        }
      case "static" =>
        calleeSet ++= CallHandler.getStaticCalleeMethod(global, sig).map(m => StaticCallee(m.getSignature))
      case _ =>
    }
    calleeSet.toSet
  }

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

  def resolveSignatureBasedCall(global: Global, sig: Signature, typ: String): ISet[JawaMethod] = {
    val callees: MSet[JawaMethod] = msetEmpty
    typ match {
      case "super" =>
        callees ++= CallHandler.getSuperCalleeMethod(global, sig)
      case "direct" =>
        callees ++= CallHandler.getDirectCalleeMethod(global, sig)
      case "static" =>
        callees ++= CallHandler.getStaticCalleeMethod(global, sig)
      case "virtual" | "interface" | _ =>
        callees ++= CallHandler.getUnknownVirtualCalleeMethods(global, sig.getClassType, sig.getSubSignature)
    }
    callees.toSet
  }
}
