/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.rfa

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.interprocedural.CallResolver
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.core.util.{ISet, MyTimeout, isetEmpty}
import org.argus.jawa.core.{ClassLoadManager, Global, JawaMethod}
import org.argus.jawa.summary.SummaryManager

class GPUReachingFactsAnalysis(
    global: Global,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    ptaresult: PTAResult,
    handler: ModelCallHandler,
    sm: SummaryManager,
    clm: ClassLoadManager,
    resolve_static_init: Boolean,
    timeout: Option[MyTimeout]) extends ReachingFactsAnalysis(global, icfg, ptaresult, handler, sm, clm, resolve_static_init, timeout) {

  def preProcess() {

  }

  override def process (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      callr: CallResolver[Node, RFAFact]): InterProceduralDataFlowGraph = {

    InterProceduralDataFlowGraph(icfg, ptaresult)
  }
}

object GPUReachingFactsAnalysis {
  System.load("")
}