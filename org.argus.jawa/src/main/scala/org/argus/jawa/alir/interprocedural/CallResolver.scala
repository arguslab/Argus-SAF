/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.interprocedural

import org.argus.jawa.alir.AlirNode
import org.argus.jawa.alir.cfg.{ICFGCallNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.rfa.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core.{Global, Signature}
import org.argus.jawa.core.util.{IMap, ISet, imapEmpty, isetEmpty}
import org.argus.jawa.summary.SummaryManager
import org.argus.jawa.summary.susaf.HeapSummaryProcessor
import org.argus.jawa.summary.susaf.rule.HeapSummary

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
trait CallResolver[N <: AlirNode, LatticeElement] {
  /**
    * It returns the facts for each callee entry node and caller return node
    */
  def resolveCall(s: ISet[LatticeElement], cs: CallStatement, callerNode: N): (IMap[N, ISet[LatticeElement]], ISet[LatticeElement])
  def getAndMapFactsForCaller(calleeS: ISet[LatticeElement], callerNode: N, calleeExitNode: N): ISet[LatticeElement]
  def needReturnNode(): Boolean
}

class ModelCallResolver(
    global: Global,
    ptaresult: PTAResult,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    sm: SummaryManager,
    handler: ModelCallHandler)(implicit heap: SimHeap) extends CallResolver[ICFGNode, RFAFact] {
  /**
    * It returns the facts for each callee entry node and caller return node
    */
  def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: ICFGNode): (IMap[ICFGNode, ISet[RFAFact]], ISet[RFAFact]) = {
    val callerContext = callerNode.getContext
    val calleeSet = CallHandler.getCalleeSet(global, cs, callerContext, ptaresult)
    val icfgCallnode = icfg.getICFGCallNode(callerContext)
    icfgCallnode.asInstanceOf[ICFGCallNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
    var returnFacts: ISet[RFAFact] = s
    calleeSet.foreach { callee =>
      val calleeSig: Signature = callee.callee
      icfg.getCallGraph.addCall(callerNode.getOwner, calleeSig)
      val calleep = global.getMethodOrResolve(calleeSig).get
      if(handler.isModelCall(calleep)) {
        returnFacts = handler.doModelCall(sm, s, calleep, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, callerContext)
      } else {
        sm.getSummary[HeapSummary](calleeSig) match {
          case Some(summary) =>
            returnFacts = HeapSummaryProcessor.process(global, summary, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, s, callerContext)
          case None => // might be due to randomly broken loop
            val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleep, s, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, callerContext)
            returnFacts = returnFacts -- delF ++ newF
        }
      }
    }
    (imapEmpty, returnFacts)
  }

  def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGNode): ISet[RFAFact] = isetEmpty

  val needReturnNode: Boolean = false
}