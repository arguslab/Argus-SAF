/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis

import hu.ssh.progressbar.ProgressBar
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.callGraph.CallGraph
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dataFlowAnalysis.{CallResolver, InterProceduralDataFlowGraph}
import org.argus.jawa.alir.interprocedural.{CallHandler, Callee}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.alir.util.TopologicalSortUtil
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._
import org.argus.jawa.core.util._

import scala.concurrent.duration._
import scala.language.postfixOps

/**
  * Created by fgwei on 6/27/17.
  */
class SummaryBasedDataFlowAnalysis(
    global: Global, sm: SummaryManager,
    handler: ModelCallHandler, resolve_static_init: Boolean,
    progressBar: ProgressBar)(implicit heap: SimHeap) {

  // Summary based analysis is context-insensitive
  Context.init_context_length(0)
  private val icfg: InterProceduralControlFlowGraph[ICFGNode] = new InterProceduralControlFlowGraph[ICFGNode]
  private val ptaresult = new PTAResult
  private val analysis = new ReachingFactsAnalysis(global, icfg, ptaresult, handler, sm, new ClassLoadManager, resolve_static_init, Some(new MyTimeout(5 minutes)))

  def build(cg: CallGraph): InterProceduralDataFlowGraph = {
    val orderedWUs: IList[WorkUnit] = TopologicalSortUtil.sort(cg.getCallMap).map{ sig =>
      val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method is not exist: " + sig))
      new WorkUnit(method, sm, handler)
    }.reverse
    ProgressBarUtil.withProgressBar("Summary based data flow analysis...", progressBar)(orderedWUs, processWU)
    ptaresult.pprint()
    InterProceduralDataFlowGraph(icfg, ptaresult)
  }

  private def processWU: WorkUnit => Unit = { wu =>
    if(!handler.isModelCall(wu.method)) {
      val initContext = new Context(global.projectName)
      val summary = wu.generateSummary(analysis, initContext, new Callr)
      println(summary)
    }
  }

  class Callr extends CallResolver[ICFGNode, RFAFact] {
    /**
      * It returns the facts for each callee entry node and caller return node
      */
    def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: ICFGNode): (IMap[ICFGNode, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      val sig = cs.signature
      val calleeSet = CallHandler.getCalleeSet(global, cs, sig, callerContext, ptaresult)
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
          sm.getSummary(calleeSig) match {
            case Some(summary) =>
              returnFacts = sm.process(summary, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, s, callerContext)
            case None => // might be due to randomly broken loop
              val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleep, s, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, callerContext)
              returnFacts = returnFacts -- delF ++ newF
          }
        }
      }
      (imapEmpty, returnFacts)
    }

    def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGNode): ISet[RFAFact] = isetEmpty

    def needReturnNode(): Boolean = false
  }
}
