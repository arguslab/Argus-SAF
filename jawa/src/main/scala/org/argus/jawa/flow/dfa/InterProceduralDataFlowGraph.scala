/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dfa

import org.argus.jawa.flow.cfg.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.pta.PTAResult

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
case class InterProceduralDataFlowGraph(icfg: InterProceduralControlFlowGraph[ICFGNode], ptaresult: PTAResult) {
  def merge(idfg: InterProceduralDataFlowGraph): InterProceduralDataFlowGraph = {
    icfg.merge(idfg.icfg)
    ptaresult.merge(idfg.ptaresult)
    this
  }
}
