/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.amandroid.alir.pta.model.{AndroidModelCallHandler, InterComponentCommunicationModel}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dfa._
import org.argus.jawa.flow.interprocedural.{CallHandler, Callee, IndirectCallee, MethodCallResolver}
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.SummaryManager

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidReachingFactsAnalysis(
    apk: ApkGlobal,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    ptaresult: PTAResult,
    handler: AndroidModelCallHandler,
    sm: SummaryManager,
    clm: ClassLoadManager,
    resolve_static_init: Boolean,
    timeout: Option[MyTimeout]) extends ReachingFactsAnalysis(apk, icfg, ptaresult, handler, sm, clm, resolve_static_init, timeout) {

  private val registerReceiverNodes: MSet[ICFGCallNode] = msetEmpty

  var currentComponent: JawaClass = _

  def build (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context): InterProceduralDataFlowGraph = {
    currentComponent = entryPointProc.getDeclaringClass
    val idfg = process(entryPointProc, initialFacts, initContext, new Callr)
    registerReceiverNodes.foreach { node =>
      InterComponentCommunicationModel.registerReceiver(apk, ptaresult, node.recvNameOpt, node.argNames, node.context)
    }
    idfg
  }

  class Callr extends MethodCallResolver(apk, ptaresult, icfg, sm, handler) {

    /**
     * It returns the facts for each callee entry node and caller return node
     */
    override def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: Node): (IMap[Node, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      val calleeSet = CallHandler.getCalleeSet(apk, cs, callerContext, ptaresult)
      val icfgCallnode = icfg.getICFGCallNode(callerContext)
      icfgCallnode.asInstanceOf[ICFGCallNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      val icfgReturnnode = icfg.getICFGReturnNode(callerContext)
      icfgReturnnode.asInstanceOf[ICFGReturnNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      var calleeFactsMap: IMap[ICFGNode, ISet[RFAFact]] = imapEmpty
      var returnFacts: ISet[RFAFact] = ReachingFactsAnalysisHelper.aggregate(s)
      val genSet: MSet[RFAFact] = msetEmpty
      val killSet: MSet[RFAFact] = msetEmpty
      var pureNormalFlag = pureNormalFlagMap.getOrElseUpdate(callerNode, true)

      val args = (cs.recvOpt ++ cs.args).toList
      calleeSet.foreach { callee =>
        val calleeSig: Signature = callee.callee
        icfg.getCallGraph.addCall(callerNode.getOwner, calleeSig)
        val calleep = apk.getMethodOrResolve(calleeSig).get
        if(handler.isICCCall(calleeSig) || handler.isModelCall(calleep)) {
          pureNormalFlag = false
          if(handler.isICCCall(calleeSig)) {
            // don't do anything for the ICC call now.
          } else { // for non-ICC-RPC model call
            callee match {
              case _: IndirectCallee =>
              // TODO: handle indirect callee here
              case _ =>
                returnFacts = handler.doModelCall(sm, s, calleep, cs.lhsOpt.map(lhs => lhs.name), cs.recvOpt, cs.args, callerContext)
                if (InterComponentCommunicationModel.isRegisterReceiver(calleeSig)) {
                  registerReceiverNodes += callerNode.asInstanceOf[ICFGCallNode]
                }
            }
          }
        } else {
          // for normal call
          if (calleep.isConcrete) {
            if (!icfg.isProcessed(calleeSig, callerContext)) {
              icfg.collectCfgToBaseGraph(calleep, callerContext, isFirst = false, needReturnNode())
              icfg.extendGraph(calleeSig, callerContext, needReturnNode = true)
            }
            val factsForCallee = getFactsForCallee(s, cs, calleep, callerContext)
            killSet ++= factsForCallee
            calleeFactsMap += (icfg.entryNode(calleeSig, callerContext) -> callee.mapFactsToCallee(factsForCallee, args, (calleep.thisOpt ++ calleep.getParamNames).toList))
          }
        }
      }
      if(pureNormalFlag) {
        if(icfg.hasEdge(icfgCallnode, icfgReturnnode)) {
          icfg.deleteEdge(icfgCallnode, icfgReturnnode)
        }
      } else pureNormalFlagMap(callerNode) = pureNormalFlag
      cs.lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, callerContext, ptaresult).toSet
          for (rdf <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              killSet += rdf
            }
          }
        case None =>
      }
      returnFacts = returnFacts -- killSet ++ genSet
      (calleeFactsMap, returnFacts)
    }

    private def getFactsForCallee(s: ISet[RFAFact], cs: CallStatement, callee: JawaMethod, callerContext: Context): ISet[RFAFact] = {
      val calleeFacts = msetEmpty[RFAFact]
      calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
      val args = (cs.recvOpt ++ cs.args).toList
      for(i <- args.indices) {
        val arg = args(i)
        val slot = VarSlot(arg)
        val value = ptaresult.pointsToSet(callerContext, slot)
        calleeFacts ++= value.map { r => RFAFact(VarSlot(slot.varName), r) }
        calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(value, s)
      }
      calleeFacts.toSet
    }
  }
}