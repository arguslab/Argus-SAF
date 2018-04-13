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

import org.argus.jawa.alir.{AlirNode, Context}
import org.argus.jawa.alir.cfg.{ICFGCallNode, ICFGNode, ICFGReturnNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.pta.{Instance, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.rfa.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.ast.{CallStatement, Location, ReturnStatement}
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.argus.jawa.core.util._
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

class MethodCallResolver(
    global: Global,
    ptaresult: PTAResult,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    sm: SummaryManager,
    handler: ModelCallHandler)(implicit heap: SimHeap) extends CallResolver[ICFGNode, RFAFact] {
  val pureNormalFlagMap: MMap[ICFGNode, Boolean] = mmapEmpty
  val returnMap: MMap[Signature, VarSlot] = mmapEmpty

  /**
    * It returns the facts for each callee entry node and caller return node
    */
  def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: ICFGNode): (IMap[ICFGNode, ISet[RFAFact]], ISet[RFAFact]) = {
    val callerContext = callerNode.getContext
    val calleeSet = CallHandler.getCalleeSet(global, cs, callerContext, ptaresult)
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
      val calleep = global.getMethodOrResolve(calleeSig).get
      if (handler.isModelCall(calleep)) {
        pureNormalFlag = false
        returnFacts = handler.doModelCall(sm, s, calleep, cs.lhsOpt.map(lhs => lhs.name), cs.recvOpt, cs.args, callerContext)
      } else {
        // for normal call
        if (calleep.isConcrete) {
          if (!icfg.isProcessed(calleeSig, callerContext)) {
            icfg.collectCfgToBaseGraph[String](calleep, callerContext, isFirst = false, needReturnNode())
            icfg.extendGraph(calleeSig, callerContext, needReturnNode = true)
          }
          val factsForCallee = getFactsForCallee(s, cs, calleep, callerContext)
          killSet ++= factsForCallee
          calleeFactsMap += (icfg.entryNode(calleeSig, callerContext) -> callee.mapFactsToCallee(factsForCallee, args, (calleep.thisOpt ++ calleep.getParamNames).toList, heap))
        }
      }
    }
    if (pureNormalFlag) {
      if (icfg.hasEdge(icfgCallnode, icfgReturnnode)) {
        icfg.deleteEdge(icfgCallnode, icfgReturnnode)
      }
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
    } else pureNormalFlagMap(callerNode) = pureNormalFlag
    returnFacts = returnFacts -- killSet ++ genSet
    (calleeFactsMap, returnFacts)
  }

  private def getFactsForCallee(s: ISet[RFAFact], cs: CallStatement, callee: JawaMethod, callerContext: Context): ISet[RFAFact] = {
    val calleeFacts = msetEmpty[RFAFact]
    calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
    val args = (cs.recvOpt ++ cs.args).toList
    for (i <- args.indices) {
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

  def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGNode): ISet[RFAFact] = {
    val result = msetEmpty[RFAFact]
    val kill = msetEmpty[RFAFact]

    /**
      * adding global facts to result
      */
    result ++= ReachingFactsAnalysisHelper.getGlobalFacts(calleeS)

    val calleeMethod = global.getMethod(calleeExitNode.getOwner).get
    val paramSlots: IList[VarSlot] = (calleeMethod.thisOpt ++ calleeMethod.getParamNames).map(VarSlot).toList

    callerNode match {
      case crn: ICFGReturnNode =>
        val calleeVarFacts = calleeS.filter(_.s.isInstanceOf[VarSlot]).map { f => (f.s.asInstanceOf[VarSlot], f.v) }
        val cs = global.getMethod(crn.getOwner).get.getBody.resolvedBody.locations(crn.locIndex).statement.asInstanceOf[CallStatement]
        val lhsSlotOpt: Option[VarSlot] = cs.lhsOpt.map { lhs => VarSlot(lhs.name) }
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
        for (i <- argSlots.indices) {
          val argSlot = argSlots(i)
          var values: ISet[Instance] = isetEmpty
          calleeVarFacts.foreach {
            case (s, v) =>
              if (paramSlots.isDefinedAt(i) && paramSlots(i) == s)
                values += v
          }
          result ++= values.map(v => new RFAFact(argSlot, v))
          val insnums = values.map(heap.getInstanceNum)
          result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
        }
        // kill the strong update for caller return node
        cs.lhsOpt match {
          case Some(lhs) =>
            val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, callerNode.getContext, ptaresult).toSet
            for (rdf <- result) {
              //if it is a strong definition, we can kill the existing definition
              if (slotsWithMark.exists { case (s, st) => s.getId == rdf.s.getId && st }) {
                kill += rdf
              }
            }
          case None =>
        }

        lhsSlotOpt.foreach { lhsSlot =>
          var values: ISet[Instance] = isetEmpty
          retSlotOpt.foreach { retSlot =>
            calleeVarFacts.foreach {
              case (s, v) =>
                if (s == retSlot) {
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

  def needReturnNode(): Boolean = true
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
      sm.getSummary[HeapSummary](calleeSig) match {
        case Some(summary) =>
          returnFacts = HeapSummaryProcessor.process(global, summary, cs.lhsOpt.map(lhs => lhs.name), cs.recvOpt, cs.args, s, callerContext)
        case None => // might be due to randomly broken loop
          if(handler.isModelCall(calleep)) {
            returnFacts = handler.doModelCall(sm, s, calleep, cs.lhsOpt.map(lhs => lhs.name), cs.recvOpt, cs.args, callerContext)
          } else {
            callee match {
              case _: IndirectCallee =>
                // TODO: handle indirect callee here
              case _ =>
                val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleep, s, cs.lhsOpt.map(lhs => lhs.name), cs.recvOpt, cs.args, callerContext)
                returnFacts = returnFacts -- delF ++ newF
            }
          }
      }
    }
    (imapEmpty, returnFacts)
  }

  def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGNode): ISet[RFAFact] = isetEmpty

  val needReturnNode: Boolean = false
}