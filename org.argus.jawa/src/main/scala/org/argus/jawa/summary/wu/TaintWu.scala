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

import org.argus.jawa.alir.controlFlowGraph.ICFGLocNode
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.{PTASlot, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.taintAnalysis.SourceAndSinkManager
import org.argus.jawa.compiler.parser.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util.{MList, MSet, msetEmpty}
import org.argus.jawa.summary.{SummaryManager, SummaryRule}

class TaintWu[T <: Global](
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    store: PTStore,
    ssm: SourceAndSinkManager[T])(implicit heap: SimHeap) extends PointsToWu(method, sm, handler, store) {

  override def processNode(node: ICFGLocNode, rules: MList[SummaryRule]): Unit = {
    val l = method.getBody.resolvedBody.location(node.locIndex)
    val context = node.getContext
    l.statement match {
      case cs: CallStatement =>
        val trackedSlots: MSet[(PTASlot, Boolean)] = msetEmpty
        val intentSlot = VarSlot(cs.rhs.argClause.arg(1))
        trackedSlots += ((intentSlot, true))
        pointsToResolve(context) = trackedSlots.toSet
      case _ =>
    }
    super.processNode(node, rules)
  }

  override def toString: String = s"TaintWu($method)"
}