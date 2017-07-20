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

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGLocNode, ICFGNode}
import org.argus.jawa.alir.dataFlowAnalysis.{CallResolver, InterProceduralDataFlowGraph}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.model.{ModelCall, ModelCallHandler}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.rule._

/**
  * Created by fgwei on 6/29/17.
  */
class WorkUnit(val method: JawaMethod, sm: SummaryManager, handler: ModelCallHandler)(implicit heap: SimHeap) {

  val global: Global = method.getDeclaringClass.global
  val thisOpt: Option[String] = method.thisOpt
  val params: ISeq[String] = method.getParamNames
  var ptaresult: PTAResult = _
  val heapMap: MMap[Instance, HeapBase] = mmapEmpty

  def generateSummary(
      analysis: ReachingFactsAnalysis,
      initContext: Context,
      callr: CallResolver[ICFGNode, RFAFact]): Summary = {
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
    val idfg = analysis.process(method, initialFacts, initContext, callr)
    ptaresult = idfg.ptaresult
    parseIDFG(idfg)
  }

  private def parseIDFG(idfg: InterProceduralDataFlowGraph): Summary = {
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

  private def processNode(node: ICFGLocNode, ptaresult: PTAResult, rules: MList[SuRule]): Unit = {
    val context = node.getContext
    val l = method.getBody.resolvedBody.location(node.locIndex)
    l.statement match {
      case as: AssignmentStatement =>
        updateHeapMap(as, context)

      case cs: CallStatement =>
        val argInss: IMap[String, ISet[Instance]] = (cs.recvOpt ++ cs.args).map { arg =>
          (arg, ptaresult.pointsToSet(context, VarSlot(arg)))
        }.toMap
        val callees = node.asInstanceOf[ICFGInvokeNode].getCalleeSet
        callees foreach { callee =>
          val calleeSig = callee.callee
          val calleep = global.getMethodOrResolve(calleeSig).get
          if(handler.isModelCall(calleep)) {
            handler.getModelCall(calleep) match {
              case Some(mc) =>
                processModelCall(mc, calleeSig, cs.recvOpt, cs.arg, context, rules)
              case None =>
            }
          } else {

          }
        }
      case rs: ReturnStatement =>
      case _ =>
    }
  }

  private def processModelCall(
      mc: ModelCall,
      signature: Signature,
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
    val summaries = sm.getSummaries(mc.safsuFile)
    summaries.get(signature.getSubSignature) match {
      case Some(summary) =>
        summary.rules foreach {
          case cr: ClearRule =>
            handleClearRule(cr, recvOpt, args, context, rules)
          case br: BinaryRule =>
            br.lhs
        }
      case None =>
    }
  }

  private def handleClearRule(
      cr: ClearRule,
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
    cr.v match {
      case _: SuThis =>
        val inss = ptaresult.pointsToSet(context, VarSlot(recvOpt.getOrElse("hack")))
        val bases = inss.flatMap(ins => heapMap.get(ins))
        println(heapMap)
        println(inss)
        println(bases)
        bases.headOption match {
          case Some(base) =>
            val heapAccesses: Seq[HeapAccess] = cr.v.heapOpt match {
              case Some(suHeap) => suHeap.indices
              case None => Seq()
            }
            rules += ClearRule(base.make(heapAccesses))
          case None =>
        }
      case a: SuArg =>
        val inss = ptaresult.pointsToSet(context, VarSlot(args(a.num)))
        val bases = inss.flatMap(ins => heapMap.get(ins))
        bases.headOption match {
          case Some(base) =>
            val heapAccesses: Seq[HeapAccess] = cr.v.heapOpt match {
              case Some(suHeap) => suHeap.indices
              case None => Seq()
            }
            rules += ClearRule(base.make(heapAccesses))
          case None =>
        }
      case g: SuGlobal =>
        rules += cr
    }
  }

  private def getLhsHeap(lhs: Expression with LHS, context: Context): ISet[HeapBase] = {
    var heapBases: ISet[HeapBase] = isetEmpty
    lhs match {
      case ae: AccessExpression =>
        val slot = VarSlot(ae.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBases += sh.make(Seq(SuFieldAccess(ae.fieldName)))
            case None =>
          }
        }
      case ie: IndexingExpression =>
        val slot = VarSlot(ie.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBases += sh.make(Seq(SuArrayAccess()))
            case None =>
          }
        }
      case _ =>
    }
    heapBases
  }

  private def updateHeapMap(
      as: AssignmentStatement,
      context: Context): Unit = {
    var heapBaseOpt: Option[HeapBase] = None
    var kill: ISet[Instance] = isetEmpty
    as.lhs match {
      case ae: AccessExpression =>
        val slot = VarSlot(ae.varSymbol.varName)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.find { ins =>
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
        inss.find { ins =>
          kill ++= ptaresult.pointsToSet(context, ArraySlot(ins))
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBaseOpt = Some(sh.make(Seq(SuArrayAccess())))
              true
            case None =>
              false
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

  override def toString: FileResourceUri = s"WorkUnit($method)"
}
