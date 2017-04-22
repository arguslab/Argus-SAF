/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachability

import org.argus.jawa.alir.interprocedural.CallHandler
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object BackwardCallChain {
  class CallChain(val sig: Signature) {
    private val callerMap: MMap[Signature, MSet[Signature]] = mmapEmpty
    def addCallers(callee: Signature, callers: ISet[Signature]): Unit = {
      callerMap.getOrElseUpdate(callee, msetEmpty) ++= callers
    }
    def getCallerMap: IMap[Signature, ISet[Signature]] = this.callerMap.map{case (k, v) => k -> v.toSet}.toMap
  }
  
  def getBackwardCallChain(global: Global, sig: Signature): CallChain = {
    val ps: ISet[JawaMethod] = global.getApplicationClasses.map(_.getDeclaredMethods).fold(isetEmpty)(iunion[JawaMethod]).filter(_.isConcrete)
    val calleeSigMethodMap: MMap[Signature, MSet[Signature]] = mmapEmpty
    ps.foreach {
      m =>
        val callees: MSet[JawaMethod] = msetEmpty
        val points = new PointsCollector().points(m.getSignature, m.getBody)
        points foreach {
          case pi: Point with Right with Invoke =>
            val typ = pi.invokeTyp
            val sig = pi.sig
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
        }
        callees.foreach{
          callee =>
            calleeSigMethodMap.getOrElseUpdate(callee.getSignature, msetEmpty) += m.getSignature
        }
    }
    val result: CallChain = new CallChain(sig)
    val worklist: MList[Signature] = mlistEmpty
    val processed: MSet[Signature] = msetEmpty
    worklist += sig
    while(worklist.nonEmpty) {
      val worksig = worklist.remove(0)
      processed += worksig
      val callerSigs: ISet[Signature] = calleeSigMethodMap.getOrElse(worksig, msetEmpty).toSet
      result.addCallers(worksig, callerSigs)
      worklist ++= callerSigs.diff(processed)
    }
    result
  }
  
}
