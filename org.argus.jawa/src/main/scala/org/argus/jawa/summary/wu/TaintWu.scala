/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.wu

import org.argus.jawa.alir.controlFlowGraph.ICFGNode
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.taintAnalysis.SourceAndSinkManager
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.{SummaryManager, SummaryRule}

class TaintWu[T <: Global](
    global: T,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T])(implicit heap: SimHeap) extends DataFlowWu[T](global, method, sm, handler) {

  override def processNode(node: ICFGNode, rules: MList[SummaryRule]): Unit = {
    ssm.getSourceAndSinkNode(global, node, None, ptaresult)

    super.processNode(node, rules)
  }

  override def toString: String = s"TaintWu($method)"
}