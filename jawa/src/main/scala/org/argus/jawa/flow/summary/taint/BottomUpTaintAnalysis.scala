/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.taint

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.taintAnalysis.SourceAndSinkManager
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.store.TaintStore
import org.argus.jawa.flow.summary.wu.{TaintSummary, TaintSummaryRule, TaintWu, WorkUnit}
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, SummaryManager, SummaryProvider}
import org.argus.jawa.core.Global
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.flow.cg.CHA

class BottomUpTaintAnalysis[T <: Global](
    global: T,
    provider: SummaryProvider,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T],
    reporter: Reporter) {

  def process(eps: ISet[Signature]): IMap[Signature, TaintStore] = {
    val sm: SummaryManager = provider.getSummaryManager
    val results: MMap[Signature, TaintStore] = mmapEmpty
    var i = 0
    eps.foreach { ep =>
      i += 1
      reporter.println(s"Processing $i/${eps.size}: ${ep.signature}")
      val cg = CHA(global, Set(ep), None)
      val analysis = new BottomUpSummaryGenerator[T, TaintSummaryRule](global, sm, handler,
        TaintSummary(_, _),
        ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
      val store = new TaintStore
      val orderedWUs: IList[WorkUnit[T, TaintSummaryRule]] = cg.topologicalSort(true).map { sig =>
        val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
        new TaintWu(global, method, sm, handler, ssm, store)
      }
      analysis.debug = true
      analysis.build(orderedWUs)
      results(ep) = store
    }
    results.toMap
  }
}
