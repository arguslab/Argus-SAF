/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.cg

import java.util.concurrent.TimeoutException

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.flow.interprocedural.{CallHandler, IndirectCallResolver}
import org.argus.jawa.flow.pta.PTAScopeManager

import scala.concurrent.duration._
import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object CHA {
  final val TITLE = "CHA"

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

    global.reporter.println(s"$TITLE done with method size ${processed.size}.")
    cg
  }

  private def sbcg(global: Global, ep: JawaMethod, cg: CallGraph, processed: MSet[String], timer: Option[MyTimeout]): Unit = {
    cg.addCalls(ep.getSignature, isetEmpty)
    val worklistAlgorithm = new WorklistAlgorithm[JawaMethod] {
      override def processElement(m: JawaMethod): Unit = {
        if(timer.isDefined) timer.get.timeoutThrow()
        processed += m.getSignature.signature
        try {
          m.getBody.resolvedBody.locations foreach { l =>
            l.statement match {
              case cs: CallStatement =>
                val callee: MSet[JawaMethod] = msetEmpty
                IndirectCallResolver.getCallResolver(global, cs.signature.classTyp, cs.signature.getSubSignature) match {
                  case Some(res) =>
                    callee ++= res.guessCallTarget(global, cs.signature)
                  case None =>
                    callee ++= CallHandler.resolveSignatureBasedCall(global, cs.signature, cs.kind)
                }
                callee foreach { callee =>
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
