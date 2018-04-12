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

import java.util.concurrent.TimeoutException

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.jawa.alir.cg.CallGraph
import org.argus.jawa.alir.interprocedural.CallHandler
import org.argus.jawa.alir.pta.PTAScopeManager
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.util._

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
    val cg = new CallGraph
    val processed: MSet[String] = msetEmpty

    def handleEntryPoint: Signature => Unit = { ep =>
      if(timer.isDefined) timer.get.refresh()
      try {
        val epmopt = global.getMethodOrResolve(ep)
        epmopt match {
          case Some(epm) =>
            if (!PTAScopeManager.shouldBypass(epm.getDeclaringClass) && epm.isConcrete) {
              sbcg(global, epm, cg, processed, timer)
            }
          case None =>
        }
      } catch {
        case te: TimeoutException =>
          global.reporter.error(TITLE, ep + ": " + te.getMessage)
      }
    }
    val progressBar = ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain")
    ProgressBarUtil.withProgressBar("Building Signature Based Call Graph...", progressBar)(entryPoints, handleEntryPoint)

    global.reporter.println(s"SignatureBasedCallGraph done with call size ${cg.getCallMap.size}.")
    cg
  }
  
  private def sbcg(global: Global, ep: JawaMethod, cg: CallGraph, processed: MSet[String], timer: Option[MyTimeout]): Unit = {
    cg.addCalls(ep.getSignature, isetEmpty)
    val worklistAlgorithm = new WorklistAlgorithm[JawaMethod] {
      override def processElement(m: JawaMethod): Unit = {
        if(timer.isDefined) timer.get.isTimeoutThrow()
        processed += m.getSignature.signature
        try {
          m.getBody.resolvedBody.locations foreach { l =>
            l.statement match {
              case cs: CallStatement =>
                CallHandler.resolveSignatureBasedCall(global, cs.signature, cs.kind) foreach { callee =>
                  cg.addCall(m.getSignature, callee.getSignature)
                  if (!processed.contains(callee.getSignature.signature) && !PTAScopeManager.shouldBypass(callee.getDeclaringClass) && callee.isConcrete) {
                    worklist +:= callee
                  }
                }
              case _ =>
            }
          }
        } catch {
          case e: Throwable => global.reporter.warning(TITLE, e.getMessage)
        }
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist +:= ep)
  }
}
