/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.interprocedural

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.{Instance, PTAResult, VarSlot}
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object CallHandler {

  def getCalleeSet(global: Global, cs: CallStatement, callerContext: Context, ptaResult: PTAResult): ISet[RFACallee] = {
    val sig = cs.signature
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
                  CallHandler.getVirtualCalleeMethod(global, ins.typ, sig) match {
                    case Left(mopt) =>
                      mopt.map(m => InstanceCallee(m.getSignature, ins)) match {
                        case Some(c) => calleeSet += c
                        case None =>
                          handleUnknown(ins.typ.toUnknown)
                      }
                    case Right(methods) =>
                      calleeSet ++= methods.map(m => UnknownCallee(m.getSignature))
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
   * check and get virtual callee procedure from GLobal. Input: equals:(Ljava/lang/Object;)Z
   */
  def getVirtualCalleeMethod(global: Global, fromType: JawaType, sig: Signature): Either[Option[JawaMethod], ISet[JawaMethod]] = {
    if(fromType.isPrimitive) { // Some obfuscation could set primitive type to object or some bug might happen
      global.reporter.error("getVirtualCalleeMethod", s"Invoke virtual method $sig with primitive type $fromType")
      Right(resolveSignatureBasedCall(global, sig, "virtual"))
    } else {
      if(fromType.isArray) {
        val typ = JavaKnowledge.OBJECT
        val from = global.getClassOrResolve(typ)
        from.getDeclaredMethod(sig.getSubSignature) match {
          case res @ Some(_) => Left(res)
          case None => // some bug might happen
            global.reporter.error("getVirtualCalleeMethod", s"Invoke virtual method $sig with array type $fromType")
            Right(resolveSignatureBasedCall(global, sig, "virtual"))
        }
      } else if(fromType.baseType.unknown) {
        val typ = fromType.removeUnknown()
        val baseRec = global.getClassOrResolve(typ)
        val methods = global.getClassHierarchy.resolveAbstractDispatch(baseRec, sig.getSubSignature)
        val m = methods.filter(m => m.isConcrete && !m.isStatic)
        Right(if(m.isEmpty) methods.filter(m => !m.isStatic) else m)
      } else {
        val typ = fromType
        val from = global.getClassOrResolve(typ)
        Left(global.getClassHierarchy.resolveConcreteDispatch(from, sig.getSubSignature))
      }
    }
  }

  /**
   * check and get super callee procedure from GLobal. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getSuperCalleeMethod(global: Global, pSig: Signature): Option[JawaMethod] = {
    val fromType = pSig.getClassType
    val pSubSig = pSig.getSubSignature
    val from = global.getClassOrResolve(fromType)
    global.getClassHierarchy.resolveConcreteDispatch(from, pSubSig)
  }

  /**
   * check and get static callee procedure from GLobal. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getStaticCalleeMethod(global: Global, procSig: Signature): Option[JawaMethod] = {
    val recType = procSig.getClassType
    val pSubSig = procSig.getSubSignature
    val from = global.getClassOrResolve(recType)
    if(from.isUnknown) {
      this.synchronized{
        global.getMethod(procSig) match {
          case None => 
            Some(from.generateUnknownJawaMethod(procSig))
          case a => a
        }
      }
    } else {
      global.getClassHierarchy.resolveConcreteDispatch(from, pSubSig)
    }
  }

  /**
   * check and get direct callee procedure from GLobal. Input: Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
   */
  def getDirectCalleeMethod(global: Global, procSig: Signature): Option[JawaMethod] = {
    val pSubSig = procSig.getSubSignature
    val recType = procSig.getClassType
    val rec = global.getClassOrResolve(recType)
    if(rec.isUnknown){
      this.synchronized{
        global.getMethod(procSig) match {
          case None => 
            Some(rec.generateUnknownJawaMethod(procSig))
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
        CallHandler.getVirtualCalleeMethod(global, sig.getClassType.toUnknown, sig) match {
          case Left(m) => callees ++= m
          case Right(m) => callees ++= m
        }
    }
    callees.toSet
  }
}
