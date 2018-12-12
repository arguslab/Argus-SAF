/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.wu

import org.argus.jawa.core._
import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGInvokeNode, ICFGLocNode, ICFGNode}
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.model.{ModelCall, ModelCallHandler}
import org.argus.jawa.flow.summary.SummaryManager
import org.argus.jawa.flow.summary.susaf.rule._

/**
  * Created by fgwei on 6/29/17.
  */
class HeapSummaryWu(
    global: Global,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler) extends DataFlowWu[Global, HeapSummaryRule](global, method, sm, handler) {

  override def needHeapSummary: Boolean = false

  override def processNode(node: ICFGNode, rules: MList[HeapSummaryRule]): Unit = {
    node match {
      case ln: ICFGLocNode =>
        val context = node.getContext
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        l.statement match {
          case as: AssignmentStatement =>
            processAssignment(as, context, rules)
          case cs: CallStatement =>
            val retOpt = cs.lhsOpt.map(lhs => lhs.name)
            val callees = node.asInstanceOf[ICFGInvokeNode].getCalleeSet
            callees foreach { callee =>
              val calleeSig = callee.callee
              val calleep = global.getMethodOrResolve(calleeSig).get
              if(handler.isModelCall(calleep)) {
                handler.getModelCall(calleep) match {
                  case Some(mc) =>
                    processModelCall(mc, calleeSig, retOpt, cs.recvOpt, cs.arg, context, rules)
                  case None =>
                    // Should not be here.
                }
              } else {
                sm.getSummary[HeapSummary](calleeSig) match {
                  case Some(su) =>
                    processSummary(su, retOpt, cs.recvOpt, cs.arg, context, rules)
                  case None =>
                  // TODO: For a loop case
                }
              }
            }
          case rs: ReturnStatement =>
            rs.varOpt match {
              case Some(v) =>
                val inss = ptaresult.pointsToSet(context, VarSlot(v.varName))
                val bases = inss.flatMap(ins => getLatestHeapBase(ins))
                if(bases.nonEmpty) {
                  rules ++= bases.map { base =>
                    BinaryRule(SuRet(None), Ops.`=`, base)
                  }
                } else {
                  rules ++= inss.map { ins =>
                    BinaryRule(SuRet(None), Ops.`+=`, processInstance(ins, context))
                  }
                }
              case None =>
            }
          case _ =>
        }
      case _ =>
    }
    // Overriding method need to invoke super to update the heap map properly.
    super.processNode(node, rules)
  }

  private def processAssignment(
      as: AssignmentStatement,
      context: Context,
      rules: MList[HeapSummaryRule]) = {
    var inss: ISet[Instance] = isetEmpty
    var lhsBases: ISet[HeapBase] = isetEmpty
    as.lhs match {
      case ae: AccessExpression =>
        inss = ptaresult.pointsToSet(context, VarSlot(ae.varSymbol.varName))
        inss.foreach { ins =>
          getLatestHeapBase(ins) match {
            case Some(hb) =>
              lhsBases += hb.make(Seq(SuFieldAccess(ae.fieldName)))
            case None =>
          }
        }
      case ie: IndexingExpression =>
        inss = ptaresult.pointsToSet(context, VarSlot(ie.varSymbol.varName))
        inss.foreach { ins =>
          getLatestHeapBase(ins) match {
            case Some(hb) =>
              lhsBases += hb.make(Seq(SuArrayAccess()))
            case None =>
          }
        }
      case sfae: StaticFieldAccessExpression =>
        inss = ptaresult.pointsToSet(context, StaticFieldSlot(sfae.name))
        inss.foreach { ins =>
          getLatestHeapBase(ins) match {
            case Some(hb) =>
              lhsBases += hb
            case None =>
          }
        }
      case _ =>
    }
    lhsBases.headOption match {
      case Some(lhsBase) =>
        as.rhs match {
          case ae: AccessExpression =>
            inss = ptaresult.pointsToSet(context, VarSlot(ae.varSymbol.varName))
            inss = inss.flatMap(ins => ptaresult.pointsToSet(context, FieldSlot(ins, ae.fieldName)))
          case ie: IndexingExpression =>
            inss = ptaresult.pointsToSet(context, VarSlot(ie.varSymbol.varName))
            inss = inss.flatMap(ins => ptaresult.pointsToSet(context, ArraySlot(ins)))
          case sfae: StaticFieldAccessExpression =>
            inss = ptaresult.pointsToSet(context, StaticFieldSlot(sfae.name))
          case ne: VariableNameExpression =>
            inss = ptaresult.pointsToSet(context, VarSlot(ne.name))
          case _ =>
        }
        val rhsBases: ISet[HeapBase] = inss.flatMap(ins => getLatestHeapBase(ins))
        rhsBases.headOption match {
          case Some(rhsBase) =>
            rules += BinaryRule(lhsBase, Ops.`=`, rhsBase)
          case None =>
            rules ++= inss.map { ins =>
              BinaryRule(lhsBase, Ops.`+=`, processInstance(ins, context))
            }
        }
      case None =>
    }
  }

  private def processModelCall(
      mc: ModelCall,
      signature: Signature,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[HeapSummaryRule]): Unit = {
    val summaries = sm.getSummariesByFile(mc.safsuFile)
    summaries.get(signature.getSubSignature) match {
      case Some(summary) =>
        processSummary(summary, retOpt, recvOpt, args, context, rules)
      case None =>
    }
  }

  private def processSummary(
      summary: HeapSummary,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[HeapSummaryRule]): Unit = {
    summary.rules foreach {
      case cr: ClearRule =>
        handleClearRule(cr, recvOpt, args, context, rules)
      case br: BinaryRule =>
        handleBinaryRule(br, retOpt, recvOpt, args, context, rules)
    }
  }

  private def processInstance(ins: Instance, context: Context): SuInstance = {
    val loc: SuLocation =
      if(ins.defSite == context) SuVirtualLocation()
      else SuConcreteLocation(ins.defSite.getCurrentLocUri)
    ins match {
      case psi: PTAConcreteStringInstance =>
        SuInstance(SuString(psi.string), loc)
      case _ =>
        SuInstance(SuJavaType(ins.typ), loc)
    }
  }

  private def processVarSlot(
      slot: VarSlot,
      hb: HeapBase,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): Option[HeapBase] = {
    val inss = ptaresult.pointsToSet(context, slot)
    val bases = inss.flatMap(ins => getLatestHeapBase(ins))
    bases.headOption match {
      case Some(base) =>
        val heapAccesses: Seq[HeapAccess] = hb.heapOpt match {
          case Some(suHeap) =>
            suHeap.indices
          case None => Seq()
        }
        Some(if(heapAccesses.isEmpty) base else base.make(heapAccesses))
      case None =>
        None
    }
  }

  private def handleHeapBase(
      hb: HeapBase,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): Option[HeapBase] = {
    var newBaseOpt: Option[HeapBase] = None
    hb match {
      case _: SuThis =>
        newBaseOpt = processVarSlot(VarSlot(recvOpt.getOrElse("hack")), hb, recvOpt, args, context)
      case sa: SuArg =>
        newBaseOpt = processVarSlot(VarSlot(args(sa.num - 1)), hb, recvOpt, args, context)
      case g: SuGlobal =>
        val newg: SuGlobal = g.heapOpt match {
          case Some(suHeap) =>
            val heapAccesses: Seq[HeapAccess] = suHeap.indices
            SuGlobal(g.fqn, Some(SuHeap(heapAccesses)))
          case None => g
        }
        newBaseOpt = Some(newg)
      case _: SuRet =>
        newBaseOpt = None
    }
    newBaseOpt
  }

  private def handleClearRule(
      cr: ClearRule,
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[HeapSummaryRule]) = {
    handleHeapBase(cr.v, recvOpt, args, context) match {
      case Some(base) =>
        rules += ClearRule(base)
      case None =>
    }
  }

  private def handleLhs(
      lhs: RuleLhs,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): Option[RuleLhs] = {
    lhs match {
      case hb: HeapBase =>
        handleHeapBase(hb, recvOpt, args, context)
    }
  }

  private def handleRhs(
      rhs: RuleRhs,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): Option[RuleRhs] = {
    rhs match {
      case hb: HeapBase =>
        handleHeapBase(hb, recvOpt, args, context)
      case sc: SuClassOf =>
        Some(sc)
      case si: SuInstance =>
        Some(si)
    }
  }

  private def handleBinaryRule(
      br: BinaryRule,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[HeapSummaryRule]) = {
    handleLhs(br.lhs, recvOpt, args, context) match {
      case Some(lhs) =>
        handleRhs(br.rhs, recvOpt, args, context) match {
          case Some(rhs) =>
            rules += BinaryRule(lhs, br.ops, rhs)
          case None =>
            br.rhs match {
              case hb: HeapBase =>
                val hinss = getHeapInstance(hb, retOpt, recvOpt, args, context)
                rules ++= hinss.map { ins =>
                  lhs match {
                    case hb: HeapBase =>
                      br.ops match {
                        case Ops.`+=` => addHeapBase(ins, hb)
                        case Ops.`=` => addHeapBase(ins, hb)
                        case Ops.`-=` => heapMap -= ins
                      }
                    case _ =>
                  }
                  BinaryRule(lhs, br.ops, processInstance(ins, context))
                }
              case _ =>
            }
        }
      case None =>
    }
  }

  override def toString: String = s"HeapSummaryWu($method)"
}