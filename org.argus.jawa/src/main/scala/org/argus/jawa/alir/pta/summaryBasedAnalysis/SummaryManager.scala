/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.summaryBasedAnalysis

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.core.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.summary.parser.SummaryParser
import org.argus.jawa.summary.rule._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryManager(implicit factory: SimHeap) {
  private val summaries: MMap[Signature, Summary] = mmapEmpty
  def register(signature: Signature, summary: Summary): Unit = summaries(signature) = summary
  def register(suCode: String): Unit = {
    val su = SummaryParser(suCode)
    this.summaries ++= su.summaries
  }

  def process(sig: Signature, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[RFAFact] = {
    var output: ISet[RFAFact] = input
    var kill: Boolean = false
    summaries.get(sig) match {
      case Some(summary) =>
        summary.rules foreach {
          case cr: ClearRule =>
            val slots = processLhs(cr.v, retOpt, recvOpt, args, output)
            output = output.filterNot(i => slots.contains(i.slot))
          case br: BinaryRule =>
            val facts = processBinaryRule(sig, br, retOpt, recvOpt, args, output, context)
            br.ops match {
              case Ops.`=` =>
                val slots = facts.map(f => f.slot)
                output = output.filterNot(i => slots.contains(i.slot)) ++ facts
                kill = true
              case Ops.`+=` => output ++= facts
              case Ops.`-=` =>
                output --= facts
                kill = true
            }
        }
      case None =>
    }
    if(kill) ReachingFactsAnalysisHelper.cleanHeap(output)
    else output
  }

  def processBinaryRule(sig: Signature, br: BinaryRule, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[RFAFact] = {
    val slots = processLhs(br.lhs, retOpt, recvOpt, args, input)
    val inss = processRhs(sig, br.rhs, recvOpt, args, input, context)
    slots.flatMap { slot =>
      inss.map { ins =>
        new RFAFact(slot, ins)
      }
    }
  }

  def processRhs(sig: Signature, rhs: RuleRhs, recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    var slots: ISet[PTASlot] = isetEmpty
    rhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"), isBase = false, isArg = false)
        slots = handleHeap(thisSlot, st.heapOpt, input)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num), isBase = false, isArg = false)
        slots = handleHeap(argSlot, sa.heapOpt, input)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(gSlot, sg.heapOpt, input)
      case st: SuInstance =>
        val newContext =
          st.loc match {
            case scl: SuConcreteLocation =>
              context.copy.setContext(sig, scl.loc)
            case _: SuVirtualLocation =>
              context
          }
        val ins = st.typ match {
          case jt: SuJavaType =>
            jt.typ.jawaName match {
              case "java.lang.String" => PTAPointStringInstance(newContext)
              case _ => PTAInstance(jt.typ, newContext)
            }
          case st: SuString => PTAConcreteStringInstance(st.str, newContext)
        }
        inss += ins
    }
    inss ++= input.filter(i => slots.contains(i.slot)).map(i => i.v)
    inss
  }

  def processLhs(lhs: RuleLhs, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact]): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    lhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"), isBase = false, isArg = false)
        slots = handleHeap(thisSlot, st.heapOpt, input)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num), isBase = false, isArg = false)
        slots = handleHeap(argSlot, sa.heapOpt, input)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(gSlot, sg.heapOpt, input)
      case sr: SuRet =>
        val retSlot = VarSlot(retOpt.getOrElse("hack"), isBase = false, isArg = false)
        slots = handleHeap(retSlot, sr.heapOpt, input)
    }
    slots
  }

  def handleHeap(slot: NameSlot, heapOpt: Option[SuHeap], input: ISet[RFAFact]): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    heapOpt match {
      case Some(heap) =>
        var currentSlots: ISet[PTASlot] = Set(slot)
        heap.indices.foreach {
          case fa: SuFieldAccess =>
            val facts = input.filter(i => currentSlots.contains(i.slot))
            currentSlots = facts.map(fact => FieldSlot(fact.v, fa.fieldName))
          case _: SuArrayAccess =>
            val facts = input.filter(i => currentSlots.contains(i.slot))
            currentSlots = facts.map(fact => ArraySlot(fact.v))
        }
        slots ++= currentSlots
      case None => slots += slot
    }
    slots
  }
}
