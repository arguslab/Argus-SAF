/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.summaryBasedAnalysis

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.ICFGNode
import org.argus.jawa.alir.dataFlowAnalysis.CallResolver
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysis, SimHeap}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.rule.Summary

/**
  * Created by fgwei on 6/29/17.
  */
class WorkUnit(val method: JawaMethod)(implicit heap: SimHeap) {

  type Node = ICFGNode

  def generateSummary(
      analysis: ReachingFactsAnalysis,
      initialFacts: ISet[RFAFact],
      initContext: Context,
      callr: CallResolver[ICFGNode, RFAFact]): Summary = {
    val idfg = analysis.process(method, initialFacts, initContext, callr)
    null
  }

  override def toString: FileResourceUri = s"WorkUnit($method)"
}
