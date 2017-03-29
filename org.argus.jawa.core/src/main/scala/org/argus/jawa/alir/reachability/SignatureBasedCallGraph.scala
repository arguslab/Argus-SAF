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

import org.argus.jawa.alir.callGraph.CallGraph
import org.argus.jawa.alir.pta.PTAScopeManager
import org.argus.jawa.core._
import org.argus.jawa.alir.util.CallHandler
import org.argus.jawa.core.util.MyTimeout
import org.sireum.util._

import scala.language.postfixOps
import scala.concurrent.duration._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object SignatureBasedCallGraph {
  final val TITLE = "SignatureBasedCallGraph"
  
  def apply(
      global: Global, 
      entryPoints: ISet[Signature],
      timer: Option[MyTimeout] = Some(new MyTimeout(1 minutes))): CallGraph = build(global, entryPoints, timer)
      
  def build(
      global: Global, 
      entryPoints: ISet[Signature],
      timer: Option[MyTimeout]): CallGraph = {
    global.reporter.echo(TITLE, s"Building SignatureBasedCallGraph with ${entryPoints.size} entry points...")
    val cg = new CallGraph
    entryPoints.foreach{
      ep =>
        if(timer.isDefined) timer.get.refresh()
        val epmopt = global.getMethodOrResolve(ep)
        epmopt match {
          case Some(epm) =>
            if(!PTAScopeManager.shouldBypass(epm.getDeclaringClass) && epm.isConcrete) {
              sbcg(global, epm, cg, timer)
            }
          case None =>
        }
    }
    global.reporter.echo(TITLE, s"SignatureBasedCallGraph Done with call size ${cg.getCallMap.size}.")
    cg
  }
  
  private def sbcg(global: Global, ep: JawaMethod, cg: CallGraph, timer: Option[MyTimeout]) = {
    val worklist: MList[JawaMethod] = mlistEmpty // Make sure that all the method in the worklist are concrete.
    val processed: MSet[String] = msetEmpty
    worklist += ep
    while(worklist.nonEmpty) {
      if(timer.isDefined) timer.get.isTimeoutThrow()
      val m = worklist.remove(0)
      processed += m.getSignature.signature
      try {
        val points = new PointsCollector().points(m.getSignature, m.getBody)
        points foreach {
          case pa: PointAsmt =>
            pa.rhs match {
              case po: PointO =>
                global.getClassOrResolve(po.obj)
              case _ =>
            }
          case pc: PointCall =>
            val pi = pc.rhs
            val typ = pi.invokeTyp
            val sig = pi.sig
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
            callees foreach {
              callee =>
                cg.addCall(m.getSignature, callee.getSignature)
                if (!processed.contains(callee.getSignature.signature) && !PTAScopeManager.shouldBypass(callee.getDeclaringClass) && callee.isConcrete) {
                  worklist += callee
                }
            }
          case _ =>
        }
      } catch {
        case e: Throwable => global.reporter.warning(TITLE, e.getMessage)
      }
    }
  }
}
