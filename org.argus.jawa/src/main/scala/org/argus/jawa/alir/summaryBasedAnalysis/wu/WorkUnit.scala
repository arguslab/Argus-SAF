/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis.wu

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGLocNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dataFlowAnalysis.{CallResolver, InterProceduralDataFlowGraph}
import org.argus.jawa.alir.interprocedural.{CallHandler, Callee}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.alir.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.util._
import org.argus.jawa.core.{ClassLoadManager, Global, JawaMethod, Signature}
import org.argus.jawa.summary.rule._

import scala.concurrent.duration._
import scala.language.postfixOps

trait WorkUnit {
  val method: JawaMethod
  val sm: SummaryManager
  def generateSummary: Summary
}

abstract class DataFlowWu(
    val method: JawaMethod,
    val sm: SummaryManager,
    handler: ModelCallHandler)(implicit heap: SimHeap) extends WorkUnit {

  val global: Global = method.getDeclaringClass.global

  // Summary based data-flow is context-insensitive
  Context.init_context_length(0)
  var resolve_static_init: Boolean = false
  val initContext = new Context(global.projectName)

  val icfg: InterProceduralControlFlowGraph[ICFGNode] = new InterProceduralControlFlowGraph[ICFGNode]
  val ptaresult = new PTAResult
  val analysis = new ReachingFactsAnalysis(global, icfg, ptaresult, handler, sm, new ClassLoadManager, resolve_static_init, Some(new MyTimeout(5 minutes)))


  val thisOpt: Option[String] = method.thisOpt
  val params: ISeq[String] = method.getParamNames
  val heapMap: MMap[Instance, HeapBase] = mmapEmpty

  def generateSummary: Summary = {
    val entryContext = initContext.copy
    entryContext.setContext(method.getSignature, method.getSignature.methodName)
    val initialFacts: ISet[RFAFact] = {
      val result = msetEmpty[RFAFact]
      method.thisOpt match {
        case Some(t) =>
          val ins = Instance.getInstance(method.getDeclaringClass.typ, entryContext, toUnknown = false)
          result += new RFAFact(VarSlot(t), ins)
          heapMap(ins) = SuThis(None)
        case None =>
      }
      method.params.indices.foreach { i =>
        val (name, typ) = method.params(i)
        if(typ.isObject) {
          val unknown = typ.jawaName match {
            case "java.lang.String" => false
            case _ => true
          }
          val ins = Instance.getInstance(typ, entryContext, unknown)
          result += new RFAFact(VarSlot(name), ins)
          heapMap(ins) = SuArg(i, None)
        }
      }
      result.toSet
    }
    val idfg = analysis.process(method, initialFacts, initContext, new Callr)
    parseIDFG(idfg)
  }

  def parseIDFG(idfg: InterProceduralDataFlowGraph): Summary = {
    val icfg = idfg.icfg
    val processed: MSet[ICFGNode] = msetEmpty
    val rules: MList[SuRule] = mlistEmpty
    val worklistAlgorithm = new WorklistAlgorithm[ICFGNode] {
      override def processElement(e: ICFGNode): Unit = {
        processed += e
        e match {
          case node: ICFGLocNode =>
            processNode(node, ptaresult, rules)
          case _ =>
        }
        worklist ++= icfg.successors(e) -- processed
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist :+= icfg.entryNode)
    Summary(method.getSignature, rules.toList)
  }

  /**
    * Overriding method need to invoke super to update the heap map properly.
    */
  def processNode(node: ICFGLocNode, ptaresult: PTAResult, rules: MList[SuRule]): Unit = {
    val context = node.getContext
    val l = method.getBody.resolvedBody.location(node.locIndex)
    l.statement match {
      case as: AssignmentStatement =>
        updateHeapMap(as, context)
      case _ =>
    }
  }

  private def updateHeapMap(
      as: AssignmentStatement,
      context: Context): Unit = {
    var heapBaseOpt: Option[HeapBase] = None
    var kill: ISet[Instance] = isetEmpty
    as.rhs match {
      case ae: AccessExpression =>
        val slot = VarSlot(ae.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          val finss = ptaresult.pointsToSet(context, FieldSlot(ins, ae.fieldName))
          finss.foreach { fins =>
            if(fins.defSite == context) {
              heapMap.get(ins) match {
                case Some(sh) =>
                  heapMap(fins) = sh.make(Seq(SuFieldAccess(ae.fieldName)))
                case None =>
              }
            }
          }
        }
      case ie: IndexingExpression =>
        val slot = VarSlot(ie.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          val ainss = ptaresult.pointsToSet(context, ArraySlot(ins))
          ainss.foreach { ains =>
            if(ains.defSite == context) {
              heapMap.get(ins) match {
                case Some(sh) =>
                  heapMap(ains) = sh.make(Seq(SuArrayAccess()))
                case None =>
              }
            }
          }
        }
      case ne: NameExpression =>
        if(ne.isStatic) {
          val slot = StaticFieldSlot(ne.name)
          val inss = ptaresult.pointsToSet(context, slot)
          inss.foreach { ins =>
            if(ins.defSite == context) {
              heapMap(ins) = SuGlobal(ne.name, None)
            }
          }
        }
      case _ =>
    }
    as.lhs match {
      case ae: AccessExpression =>
        val slot = VarSlot(ae.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          kill ++= ptaresult.pointsToSet(context, FieldSlot(ins, ae.fieldName))
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBaseOpt = Some(sh.make(Seq(SuFieldAccess(ae.fieldName))))
              true
            case None =>
              false
          }
        }
      case ie: IndexingExpression =>
        val slot = VarSlot(ie.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          kill ++= ptaresult.pointsToSet(context, ArraySlot(ins))
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBaseOpt = Some(sh.make(Seq(SuArrayAccess())))
              true
            case None =>
              false
          }
        }
      case ne: NameExpression =>
        if(ne.isStatic) {
          val slot = StaticFieldSlot(ne.name)
          val inss = ptaresult.pointsToSet(context, slot)
          kill ++= inss
          inss.foreach { ins =>
            heapMap.get(ins) match {
              case Some(sh) =>
                heapBaseOpt = Some(sh)
              case None =>
                heapBaseOpt = Some(SuGlobal(ne.name, None))
            }
          }
        }
      case _ =>
    }
    val (gen, _) = ReachingFactsAnalysisHelper.processRHS(as.rhs, as.typOpt, context, ptaresult)
    heapBaseOpt match {
      case Some(heapBase) =>
        setHeapMap(heapBase, gen, kill)
      case None =>
    }
  }

  private def setHeapMap(
                          heapBase: HeapBase,
                          gen: ISet[Instance],
                          kill: ISet[Instance]): Unit = {
    heapMap --= kill
    gen.foreach { i =>
      heapMap(i) = heapBase
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

  override def toString: String = s"DataFlowWu($method)"
}