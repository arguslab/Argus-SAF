/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary

import hu.ssh.progressbar.ProgressBar
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.summary.susaf.rule.HeapSummary
import org.argus.jawa.flow.summary.wu.{DataFlowWu, HeapSummaryWu, WorkUnit}

/**
  * Created by fgwei on 6/27/17.
  */
class BottomUpSummaryGenerator[T <: Global, S <: SummaryRule](
    global: Global,
    sm: SummaryManager,
    handler: ModelCallHandler,
    suGen: (Signature, IList[S]) => Summary[S],
    progressBar: ProgressBar) {

  var debug: Boolean = false

  def build(orderedWUs: IList[WorkUnit[T, S]]): Unit = {
    TimeUtil.timed(s"BottomUpSummaryGenerator with ${orderedWUs.size} methods. Running Time", global.reporter) {
      ProgressBarUtil.withProgressBar("Summary based data flow analysis...", progressBar)(orderedWUs, processWU)
    }
  }

  private def processWU: WorkUnit[T, S] => Unit = { wu =>
    if (wu.needProcess(handler)) {
      try {
        wu.initFn()
        if (wu.needHeapSummary) {
          generateHeapSummary(wu.method) match {
            case Some(w) =>
              wu match {
                case dfw: DataFlowWu[T, S] => dfw.setIDFG(w.getIDFG, w.getHeapMap)
                case _ =>
              }
            case None =>
          }
        }
        val summary = wu.generateSummary(suGen)
        sm.register(wu.method.getSignature, summary)
      } catch {
        case e: Exception =>
          if(debug) {
            e.printStackTrace()
          }
      } finally {
        wu.finalFn()
      }
    }
  }

  private def generateHeapSummary(method: JawaMethod): Option[HeapSummaryWu] = {
    if(!sm.contains(method.getSignature)) {
      val wu = new HeapSummaryWu(global, method, sm, handler)
      val summary = wu.generateSummary(HeapSummary(_, _))
      sm.register(method.getSignature, summary)
      Some(wu)
    } else None
  }
}