/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.jawa.core.util._

import org.argus.amandroid.alir.pta.model.{AndroidModelCallHandler, InterComponentCommunicationModel}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataFlowAnalysis._
import org.argus.jawa.alir.interprocedural.{CallHandler, Callee}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.alir.pta.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidReachingFactsAnalysis(
    apk: ApkGlobal,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    ptaresult: PTAResult,
    handler: ModelCallHandler,
    sm: SummaryManager,
    clm: ClassLoadManager,
    resolve_static_init: Boolean,
    timeout: Option[MyTimeout])(implicit heap: SimHeap) extends ReachingFactsAnalysis(apk, icfg, ptaresult, handler, sm, clm, resolve_static_init, timeout) {

  private val registerReceiverNodes: MSet[ICFGCallNode] = msetEmpty

  var currentComponent: JawaClass = _

  def build (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context): InterProceduralDataFlowGraph = {
    currentComponent = entryPointProc.getDeclaringClass
    val idfg = process(entryPointProc, initialFacts, initContext, new Callr)
    registerReceiverNodes.foreach { node =>
      InterComponentCommunicationModel.registerReceiver(apk, ptaresult, node.retNameOpt, node.argNames.headOption, node.argNames.tail, node.context)
    }
    idfg
  }

  class Callr extends CallResolver[Node, RFAFact] {
    val pureNormalFlagMap: MMap[Node, Boolean] = mmapEmpty
    val returnMap: MMap[Signature, VarSlot] = mmapEmpty
    /**
     * It returns the facts for each callee entry node and caller return node
     */
    def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: Node): (IMap[Node, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      val sig = cs.signature
      val calleeSet = CallHandler.getCalleeSet(apk, cs, sig, callerContext, ptaresult)
      val icfgCallnode = icfg.getICFGCallNode(callerContext)
      icfgCallnode.asInstanceOf[ICFGCallNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      val icfgReturnnode = icfg.getICFGReturnNode(callerContext)
      icfgReturnnode.asInstanceOf[ICFGReturnNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      var calleeFactsMap: IMap[ICFGNode, ISet[RFAFact]] = imapEmpty
      var returnFacts: ISet[RFAFact] = s
      val genSet: MSet[RFAFact] = msetEmpty
      val killSet: MSet[RFAFact] = msetEmpty
      var pureNormalFlag = pureNormalFlagMap.getOrElseUpdate(callerNode, true)

      val args = (cs.recvOpt ++ cs.args).toList
      calleeSet.foreach { callee =>
        val calleeSig: Signature = callee.callee
        icfg.getCallGraph.addCall(callerNode.getOwner, calleeSig)
        val calleep = apk.getMethodOrResolve(calleeSig).get
        if(AndroidModelCallHandler.isICCCall(calleeSig) || AndroidModelCallHandler.isRPCCall(apk, currentComponent.getType, calleeSig) || AndroidModelCallHandler.isModelCall(calleep)) {
          pureNormalFlag = false
          if(AndroidModelCallHandler.isICCCall(calleeSig)) {
            // don't do anything for the ICC call now.
          } else if (AndroidModelCallHandler.isRPCCall(apk, currentComponent.getType, calleeSig)) {
            // don't do anything for the RPC call now.
          } else { // for non-ICC-RPC model call
            returnFacts = AndroidModelCallHandler.doModelCall(sm, s, calleep, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, callerContext)
            if(InterComponentCommunicationModel.isRegisterReceiver(calleeSig)) {
              registerReceiverNodes += callerNode.asInstanceOf[ICFGCallNode]
            }
          }
        } else {
          // for normal call
          if (calleep.isConcrete) {
            if (!icfg.isProcessed(calleeSig, callerContext)) {
              icfg.collectCfgToBaseGraph[String](calleep, callerContext, isFirst = false, needReturnNode = true)
              icfg.extendGraph(calleeSig, callerContext, needReturnNode = true)
            }
            val factsForCallee = getFactsForCallee(s, cs, calleep, callerContext)
            killSet ++= factsForCallee
            calleeFactsMap += (icfg.entryNode(calleeSig, callerContext) -> callee.mapFactsToCallee(factsForCallee, args, (calleep.thisOpt ++ calleep.getParamNames).toList, heap))
          }
        }
      }
      if(pureNormalFlag) {
        if(icfg.hasEdge(icfgCallnode, icfgReturnnode)) {
          icfg.deleteEdge(icfgCallnode, icfgReturnnode)
        }
        cs.lhsOpt match {
          case Some(lhs) =>
            val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerContext, ptaresult).toSet
            for (rdf <- s) {
              //if it is a strong definition, we can kill the existing definition
              if (slotsWithMark.contains(rdf.s, true)) {
                killSet += rdf
              }
            }
          case None =>
        }
      } else pureNormalFlagMap(callerNode) = pureNormalFlag
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
        calleeFacts ++= value.map { r => new RFAFact(VarSlot(slot.varName), r) }
        val instnums = value.map(heap.getInstanceNum)
        calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(instnums, s)
      }
      calleeFacts.toSet
    }

    private def isReturnJump(loc: Location): Boolean = {
      loc.statement.isInstanceOf[ReturnStatement]
    }

    def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: Node, calleeExitNode: Node): ISet[RFAFact] = {
      val result = msetEmpty[RFAFact]
      val kill = msetEmpty[RFAFact]
      /**
       * adding global facts to result
       */
      result ++= ReachingFactsAnalysisHelper.getGlobalFacts(calleeS)

      val calleeMethod = apk.getMethod(calleeExitNode.getOwner).get
      val paramSlots: IList[VarSlot] = (calleeMethod.thisOpt ++ calleeMethod.getParamNames).map(VarSlot).toList

      callerNode match {
        case crn: ICFGReturnNode =>
          val calleeVarFacts = calleeS.filter(_.s.isInstanceOf[VarSlot]).map{f=>(f.s.asInstanceOf[VarSlot], f.v)}
          val cs = apk.getMethod(crn.getOwner).get.getBody.resolvedBody.locations(crn.locIndex).statement.asInstanceOf[CallStatement]
          val lhsSlotOpt: Option[VarSlot] = cs.lhsOpt.map{lhs=>VarSlot(lhs.lhs.varName)}
          val retSlotOpt: Option[VarSlot] = returnMap.get(calleeMethod.getSignature) match {
            case Some(v) => Some(v)
            case None =>
              calleeMethod.getBody.resolvedBody.locations.find(l => isReturnJump(l)) match {
                case Some(r) =>
                  r.statement.asInstanceOf[ReturnStatement].varOpt match {
                    case Some(n) =>
                      val s = VarSlot(n.varName)
                      returnMap(calleeMethod.getSignature) = s
                      Some(s)
                    case None => None
                  }
                case None => None
              }
          }
          val argSlots = (cs.recvOpt ++ cs.args).toList.map(VarSlot)
          for(i <- argSlots.indices) {
            val argSlot = argSlots(i)
            var values: ISet[Instance] = isetEmpty
            calleeVarFacts.foreach{
              case (s, v) =>
                if(paramSlots.isDefinedAt(i) && paramSlots(i) == s)
                  values += v
            }
            result ++= values.map(v=> new RFAFact(argSlot, v))
            val insnums = values.map(heap.getInstanceNum)
            result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
          }
          // kill the strong update for caller return node
          cs.lhsOpt match {
            case Some(lhs) =>
              val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerNode.getContext, ptaresult).toSet
              for (rdf <- result) {
                //if it is a strong definition, we can kill the existing definition
                if (slotsWithMark.exists{case (s, st) => s.getId == rdf.s.getId && st}) {
                  kill += rdf
                }
              }
            case None =>
          }

          lhsSlotOpt.foreach { lhsSlot =>
            var values: ISet[Instance] = isetEmpty
            retSlotOpt.foreach { retSlot =>
              calleeVarFacts.foreach{
                case (s, v) =>
                  if(s == retSlot){
                    values += v
                  }
              }
            }
            result ++= values.map(v => new RFAFact(lhsSlot, v))
            val insnums = values.map(heap.getInstanceNum)
            result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
          }
        case _: ICFGNode =>
      }
      result.toSet -- kill
    }
  }
}