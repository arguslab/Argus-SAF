/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta.rfa

import java.util.concurrent.TimeoutException

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.dfa._
import org.argus.jawa.flow.interprocedural.CallResolver
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.pta._
import org.argus.jawa.core.ast._
import org.argus.jawa.core.util._
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.argus.jawa.flow.summary.SummaryManager

import scala.collection.immutable.BitSet

/**
  * Created by fgwei on 6/29/17.
  */
class ReachingFactsAnalysis(
    global: Global,
    icfg: InterProceduralControlFlowGraph[ICFGNode],
    ptaresult: PTAResult,
    handler: ModelCallHandler,
    sm: SummaryManager,
    clm: ClassLoadManager,
    resolve_static_init: Boolean,
    timeout: Option[MyTimeout]) {

  type Node = ICFGNode

  var mdf: MonotoneDataFlowAnalysisResult[ICFGNode, RFAFact] = _

  def process (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      callr: CallResolver[Node, RFAFact]): InterProceduralDataFlowGraph = {
    val gen = new Gen
    val kill = new Kill
    val initial: ISet[RFAFact] = isetEmpty
    val ip = new Ip(icfg)
    icfg.collectCfgToBaseGraph(entryPointProc, initContext, isFirst = true, callr.needReturnNode())
    initialFacts.foreach { fact =>
      val entryContext = icfg.entryNode.getContext.copy
      ptaresult.addInstance(entryContext, fact.slot, fact.ins)
    }
    val iota: ISet[RFAFact] = initialFacts + RFAFact(StaticFieldSlot("Analysis.RFAiota"), PTAInstance(JavaKnowledge.OBJECT.toUnknown, initContext.copy))
    try {
      mdf = MonotoneDataFlowAnalysisFramework[ICFGNode, RFAFact, Context](icfg,
        forward = true, lub = true, ip, gen, kill, Some(callr), iota, initial)
    } catch {
      case te: TimeoutException =>
        global.reporter.warning("ReachingFactsAnalysis", entryPointProc.getSignature + " " + te.getMessage)
    }
    val finalFacts = mdf.entrySet(icfg.exitNode)
    finalFacts.foreach { fact =>
      val exitContext = icfg.exitNode.getContext.copy
      ptaresult.addInstance(exitContext, fact.slot, fact.ins)
    }
    InterProceduralDataFlowGraph(icfg, ptaresult)
  }

  class Gen extends MonotonicFunction[ICFGNode, RFAFact] {

    protected def isInterestingAssignment(a: Assignment): Boolean = {
      a match{
        case as: AssignmentStatement =>
          as.rhs match {
            case _: CastExpression => true
            case _: ConstClassExpression => true
            case _: ExceptionExpression => true
            case _: Expression with New => true
            case _: NullExpression => true
            case _ =>
              as.kind == "object"
          }
        case _ => false
      }
    }

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: ICFGNode): ISet[RFAFact] = {
      var result: ISet[RFAFact] = isetEmpty
      if(isInterestingAssignment(a)) {
        val lhsOpt = a.getLhs
        val rhs = a.getRhs
        val heapUnknownFacts = ReachingFactsAnalysisHelper.getHeapUnknownFacts(rhs, currentNode.getContext, ptaresult)
        result ++= heapUnknownFacts
        val slots: IMap[PTASlot, Boolean] = lhsOpt match {
          case Some(lhs) => ReachingFactsAnalysisHelper.processLHS(lhs, currentNode.getContext, ptaresult)
          case None => imapEmpty
        }
        val (values, extraFacts) = ReachingFactsAnalysisHelper.processRHS(rhs, currentNode.getContext, ptaresult)
        slots.foreach {
          case (slot, _) =>
            result ++= values.map{v => RFAFact(slot, v)}
        }
        result ++= extraFacts
      }
      val exceptionFacts: ISet[RFAFact] = ReachingFactsAnalysisHelper.getExceptionFacts(a, s, currentNode.getContext)
      result ++= exceptionFacts
      result
    }

    def apply(s: ISet[RFAFact], e: Statement, currentNode: ICFGNode): ISet[RFAFact] = {
      var result: ISet[RFAFact] = isetEmpty
      e match{
        case as: AssignmentStatement =>
          result ++= handleAssignmentStatement(s, as, currentNode)
        case ta: ThrowStatement =>
          val slot = VarSlot(ta.varSymbol.varName)
          val value = s.filter(_.s == slot).map(_.v)
          result ++= value.map(RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME), _))
        case _ =>
      }
      result
    }
  }

  class Kill extends MonotonicFunction[ICFGNode, RFAFact] {

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: ICFGNode): ISet[RFAFact] = {
      var result = ReachingFactsAnalysisHelper.aggregate(s)
      val lhsOpt = a.getLhs
      lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, currentNode.getContext, ptaresult).toSet
          for (rdf <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              result = result - rdf
            }
          }
        case None =>
      }

      result
    }

    def apply(s: ISet[RFAFact], e: Statement, currentNode: ICFGNode): ISet[RFAFact] = {
      e match {
        case as: AssignmentStatement => handleAssignmentStatement(s, as, currentNode)
        case _ => s
      }
    }
  }

  private def checkAndLoadClassFromHierarchy(me: JawaClass, currentNode: Node): Unit = {
    if(me.hasSuperClass){
      checkAndLoadClassFromHierarchy(me.getSuperClass, currentNode)
    }
    val bitset = currentNode.getLoadedClassBitSet
    if(!clm.isLoaded(me, bitset)) {
      currentNode.setLoadedClassBitSet(clm.loadClass(me, bitset))
      if(me.declaresStaticInitializer) {
        val p = me.getStaticInitializer.get
        if(resolve_static_init) {
          if(handler.isModelCall(p)) {
            ReachingFactsAnalysisHelper.getUnknownObjectForClinit(p, currentNode.getContext)
          } else if(!this.icfg.isProcessed(p.getSignature, currentNode.getContext)) { // for normal call
            val nodes = this.icfg.collectCfgToBaseGraph(p, currentNode.getContext, isFirst = false, needReturnNode = true)
            nodes.foreach{n => n.setLoadedClassBitSet(clm.loadClass(me, bitset))}
            val clinitVirEntryContext = currentNode.getContext.copy.setContext(p.getSignature, "Entry")
            val clinitVirExitContext = currentNode.getContext.copy.setContext(p.getSignature, "Exit")
            val clinitEntry = this.icfg.getICFGEntryNode(clinitVirEntryContext)
            val clinitExit = this.icfg.getICFGExitNode(clinitVirExitContext)
            this.icfg.addEdge(currentNode, clinitEntry)
            this.icfg.addEdge(clinitExit, currentNode)
          }
        }
      }
    }
  }

  private def checkClass(recTyp: JawaType, currentNode: Node): Unit = {
    val rec = global.getClassOrResolve(recTyp)
    checkAndLoadClassFromHierarchy(rec, currentNode)
  }

  /**
    * A.<clinit>() will be called under four kinds of situation: v0 = new A, A.f = v1, v2 = A.f, and A.foo()
    * also for v0 = new B where B is descendant of A, first we call A.<clinit>, later B.<clinit>.
    */
  protected def checkAndLoadClasses(a: Statement, currentNode: Node): Unit = {
    a match {
      case as: AssignmentStatement =>
        as.lhs match {
          case sfae: StaticFieldAccessExpression =>
            val slot = StaticFieldSlot(sfae.name)
            val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(slot.fqn)
            checkClass(recTyp, currentNode)
          case _ =>
        }
        as.rhs match {
          case ne: Expression with New =>
            val typ = ne.typ
            checkClass(typ, currentNode)
          case sfae: StaticFieldAccessExpression =>
            val slot = StaticFieldSlot(sfae.name)
            val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(slot.fqn)
            checkClass(recTyp, currentNode)
          case _ =>
        }
      case cs: CallStatement =>
        if (cs.kind == "static") {
          val recTyp = a.asInstanceOf[CallStatement].signature.getClassType
          checkClass(recTyp, currentNode)
        }
      case _ =>
    }
  }

  class Ip(icfg: InterProceduralControlFlowGraph[ICFGNode]) extends InterIngredientProvider[RFAFact](global, icfg) {

    override def preProcess(node: ICFGNode, statement: Statement, s: ISet[RFAFact]): Unit = {
      checkAndLoadClasses(statement, node)
      statement match {
        case a: AssignmentStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultRHS(a.rhs, node.getContext, s, ptaresult)
          ReachingFactsAnalysisHelper.updatePTAResultLHS(a.lhs, node.getContext, s, ptaresult)
        case _: EmptyStatement =>
        case m: MonitorStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultVar(m.varSymbol.varName, node.getContext, s, ptaresult)
        case j: Jump =>
          j match {
            case cs: CallStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultCallJump(cs, node.getContext, s, ptaresult, afterCall = false)
            case _: GotoStatement =>
            case is: IfStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultExp(is.cond, node.getContext, s, ptaresult)
            case rs: ReturnStatement =>
              rs.varOpt match {
                case Some(v) =>
                  ReachingFactsAnalysisHelper.updatePTAResultVar(v.varName, node.getContext, s, ptaresult)
                case None =>
              }
            case ss: SwitchStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultVar(ss.condition.varName, node.getContext, s, ptaresult)
          }
        case t: ThrowStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultVar(t.varSymbol.varName, node.getContext, s, ptaresult)
      }
    }

    override def postProcess(node: ICFGNode, statement: Statement, s: ISet[RFAFact]): Unit = {
      statement match {
        case cs: CallStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultCallJump(cs, node.getContext, s, ptaresult, afterCall = true)
        case _ =>
      }
      statement match {
        case a: Assignment =>
          a.getLhs match {
            case Some(lhs) =>
              lhs match {
                case vne: VariableNameExpression =>
                  val slot = VarSlot(vne.name)
                  s.filter { fact => fact.s == slot }.foreach(f => ptaresult.addInstance(node.getContext, slot, f.v))
                case sfae: StaticFieldAccessExpression =>
                  val slot = StaticFieldSlot(sfae.name)
                  s.filter { fact => fact.s == slot }.foreach(f => ptaresult.addInstance(node.getContext, slot, f.v))
                case _ =>
              }
            case None =>
          }
        case _ =>
      }
    }

    override def onPreVisitNode(node: ICFGNode, preds: CSet[ICFGNode]): Unit = {
      val bitset = if(preds.nonEmpty)preds.map{_.getLoadedClassBitSet}.reduce{ (x, y) => x.intersect(y)} else BitSet.empty
      node.setLoadedClassBitSet(bitset)
    }

    override def onPostVisitNode(node: ICFGNode, succs: CSet[ICFGNode]): Unit = {
      timeout foreach (_.timeoutThrow())
    }
  }
}
