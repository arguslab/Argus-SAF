/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.wu

import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.jawa.alir.controlFlowGraph.{ICFGLocNode, ICFGNode}
import org.argus.jawa.alir.pta.{PTASlot, VarSlot}
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.compiler.parser.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.wu.{PTStore, PointsToWu}
import org.argus.jawa.summary.{SummaryManager, SummaryRule}

class IntentWu(
    global: Global,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    store: PTStore,
    key: String)(implicit heap: SimHeap) extends PointsToWu[Global](global, method, sm, handler, store, key) {

  override def processNode(node: ICFGNode, rules: MList[SummaryRule]): Unit = {
    node match {
      case ln: ICFGLocNode =>
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        val context = node.getContext
        l.statement match {
          case cs: CallStatement if InterComponentCommunicationModel.isIccOperation(cs.signature) =>
            val trackedSlots: MSet[(PTASlot, Boolean)] = msetEmpty
            val intentSlot = VarSlot(cs.rhs.argClause.arg(1))
            trackedSlots += ((intentSlot, true))
            pointsToResolve(context) = trackedSlots.toSet
          case _ =>
        }
      case _ =>
    }
    super.processNode(node, rules)
  }

  override def toString: String = s"IntentWu($method)"
}