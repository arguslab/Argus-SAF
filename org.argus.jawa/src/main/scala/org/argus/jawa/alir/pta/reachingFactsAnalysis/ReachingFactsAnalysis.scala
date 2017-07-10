/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis

import java.util.concurrent.TimeoutException

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dataFlowAnalysis._
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.alir.pta._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.util._
import org.argus.jawa.core._

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
    timeout: Option[MyTimeout])(implicit heap: SimHeap) {

  type Node = ICFGNode

  def process (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      callr: CallResolver[Node, RFAFact]): InterProceduralDataFlowGraph = {
    val gen = new Gen
    val kill = new Kill
    val initial: ISet[RFAFact] = isetEmpty
    val ip = new Ip(icfg)
    icfg.collectCfgToBaseGraph(entryPointProc, initContext, isFirst = true, needReturnNode = true)
    val iota: ISet[RFAFact] = initialFacts + new RFAFact(StaticFieldSlot("Analysis.RFAiota"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, initContext.copy))
    try {
      MonotoneDataFlowAnalysisFramework[ICFGNode, RFAFact, Context](icfg,
        forward = true, lub = true, ip, gen, kill, Some(callr), iota, initial)
    } catch {
      case te: TimeoutException =>
        global.reporter.warning("ReachingFactsAnalysis", entryPointProc.getSignature + " " + te.getMessage)
    }
    //    icfg.toDot(new PrintWriter(System.out))
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
            case _: NewExpression => true
            case _: NullExpression => true
            case _ =>
              as.kind == "object"
          }
        case _ => false
      }
    }

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: ICFGNode): ISet[RFAFact] = {
      val typ = a match {
        case as: AssignmentStatement => as.typOpt
        case _ => None
      }
      var result: ISet[RFAFact] = isetEmpty
      if(isInterestingAssignment(a)) {
        val lhsOpt = a.getLhs
        val rhs = a.getRhs
        val slots: IMap[PTASlot, Boolean] = lhsOpt match {
          case Some(lhs) => ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult)
          case None => imapEmpty
        }
        val (values, extraFacts) = ReachingFactsAnalysisHelper.processRHS(rhs, typ, currentNode.getContext, ptaresult)
        slots.foreach {
          case (slot, _) =>
            result ++= values.map{v => new RFAFact(slot, v)}
        }
        result ++= extraFacts
        val heapUnknownFacts = ReachingFactsAnalysisHelper.getHeapUnknownFacts(rhs, currentNode.getContext, ptaresult)
        result ++= heapUnknownFacts
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
          result ++= value.map(new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME), _))
        case _ =>
      }
      result
    }
  }

  class Kill extends MonotonicFunction[ICFGNode, RFAFact] {

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: ICFGNode): ISet[RFAFact] = {
      val typ = a match {
        case as: AssignmentStatement => as.typOpt
        case _ => None
      }
      var result = s
      val lhsOpt = a.getLhs
      lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult).toSet
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
          case ne: NameExpression =>
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne)
            slot match {
              case slot1: StaticFieldSlot =>
                val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(slot1.fqn)
                checkClass(recTyp, currentNode)
              case _ =>
            }
          case _ =>
        }
        as.rhs match {
          case ne: NewExpression =>
            val typ = ne.typ
            checkClass(typ, currentNode)
          case ne: NameExpression =>
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne)
            if (slot.isInstanceOf[StaticFieldSlot]) {
              val fqn = ne.name
              val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(fqn)
              checkClass(recTyp, currentNode)
            }
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
          ReachingFactsAnalysisHelper.updatePTAResultRHS(a.rhs, a.typOpt, node.getContext, s, ptaresult)
          ReachingFactsAnalysisHelper.updatePTAResultLHS(a.lhs, node.getContext, s, ptaresult)
        case _: EmptyStatement =>
        case m: MonitorStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultVar(m.varSymbol.varName, node.getContext, s, ptaresult)
        case j: Jump =>
          j match {
            case cs: CallStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultCallJump(cs, node.getContext, s, ptaresult)
            case _: GotoStatement =>
            case is: IfStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultExp(is.cond, None, node.getContext, s, ptaresult)
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

    override def postProcess(node: ICFGNode, s: ISet[RFAFact]): Unit = {
    }

    override def onPreVisitNode(node: ICFGNode, preds: CSet[ICFGNode]): Unit = {
      val bitset = if(preds.nonEmpty)preds.map{_.getLoadedClassBitSet}.reduce{ (x, y) => x.intersect(y)} else BitSet.empty
      node.setLoadedClassBitSet(bitset)
    }

    override def onPostVisitNode(node: ICFGNode, succs: CSet[ICFGNode]): Unit = {
      timeout foreach (_.isTimeoutThrow())
    }
  }
}
