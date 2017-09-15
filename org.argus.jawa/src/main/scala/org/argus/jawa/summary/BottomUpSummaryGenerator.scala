/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary

import hu.ssh.progressbar.ProgressBar
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.susaf.rule.HeapSummary
import org.argus.jawa.summary.wu.{DataFlowWu, HeapSummaryWu, WorkUnit}

/**
  * Created by fgwei on 6/27/17.
  */
class BottomUpSummaryGenerator[T <: Global](
    global: Global,
    sm: SummaryManager,
    handler: ModelCallHandler,
    suGen: (Signature, IList[SummaryRule]) => Summary,
    progressBar: ProgressBar)(implicit heap: SimHeap) {

  def build(orderedWUs: IList[WorkUnit[T]]): Unit = {
    ProgressBarUtil.withProgressBar("Summary based data flow analysis...", progressBar)(orderedWUs, processWU)
  }

  private def processWU: WorkUnit[T] => Unit = { wu =>
    if (!handler.isModelCall(wu.method)) {
      if(wu.needHeapSummary) {
        generateHeapSummary(wu.method) match {
          case Some(w) =>
            wu match {
              case dfw: DataFlowWu[T] => dfw.setIDFG(w.getIDFG)
              case _ =>
            }
          case None =>
        }
      }
      val summary = wu.generateSummary(suGen)
      sm.register(wu.method.getSignature, summary)
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
