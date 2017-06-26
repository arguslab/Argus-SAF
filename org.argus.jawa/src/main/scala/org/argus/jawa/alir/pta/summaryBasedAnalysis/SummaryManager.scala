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

import com.google.common.base.Charsets
import com.google.common.io.Resources
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.core.{JavaKnowledge, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.parser.SummaryParser
import org.argus.jawa.summary.rule._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryManager(implicit factory: SimHeap) {

  //  Map from signature to Summary
  private val summaries: MMap[Signature, Summary] = mmapEmpty
  def register(signature: Signature, summary: Summary): Unit = summaries(signature) = summary
  def register(suCode: String): IMap[Signature, Summary] = {
    val su = SummaryParser(suCode)
    this.summaries ++= su.summaries
    su.summaries
  }

  // Map from file name to sub signature to summary
  private var summaryFiles: IMap[String, IMap[String, Summary]] = imapEmpty
  // Internal use only
  def registerFileInternal(safsuPath: String): Unit = {
    val url = Resources.getResource(safsuPath)
    val code = Resources.toString(url, Charsets.UTF_8)
    val s = SummaryParser(code).summaries.map{case (k, v) => k.getSubSignature -> v}
    this.summaryFiles += FileUtil.filename(url.toString) -> s
  }

  /**
    * Using summary file name to get corresponding summaries.
    * @param fileName The file name like: String.safsu
    */
  def getSummaries(fileName: String): IMap[String, Summary] = {
    this.summaryFiles.getOrElse(fileName, imapEmpty)
  }

  def process(sig: Signature, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[RFAFact] = {
    summaries.get(sig) match {
      case Some(summary) =>
        process(summary, retOpt, recvOpt, args, input, context)
      case None =>
        isetEmpty
    }
  }

  def process(summary: Summary, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[RFAFact] = {
    var output: ISet[RFAFact] = input
    var kill: Boolean = false
    summary.rules foreach {
      case cr: ClearRule =>
        val slots = processLhs(summary.signature, cr.v, retOpt, recvOpt, args, output, context)
        val heaps = ReachingFactsAnalysisHelper.getRelatedHeapFactsFrom(output.filter(i => slots.contains(i.slot)), output)
        output --= heaps
        kill = true
      case br: BinaryRule =>
        val facts = processBinaryRule(summary.signature, br, retOpt, recvOpt, args, output, context)
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
    if(kill) ReachingFactsAnalysisHelper.cleanHeap(output)
    else output
  }

  def processBinaryRule(sig: Signature, br: BinaryRule, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context): ISet[RFAFact] = {
    val slots = processLhs(sig, br.lhs, retOpt, recvOpt, args, input, context)
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
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(sig, thisSlot, st.heapOpt, recvOpt, args, input, context, isLhs = false)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num))
        slots = handleHeap(sig, argSlot, sa.heapOpt, recvOpt, args, input, context, isLhs = false)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(sig, gSlot, sg.heapOpt, recvOpt, args, input, context, isLhs = false)
      case sc: SuClassOf =>
        val newContext = sc.loc match {
          case scl: SuConcreteLocation =>
            context.copy.setContext(sig, scl.loc)
          case _: SuVirtualLocation =>
            context
        }
        val rhsInss = processRhs(sig, sc.rhs, recvOpt, args, input, context)
        inss ++= rhsInss.map { rhsins =>
          PTAConcreteStringInstance(JavaKnowledge.formatTypeToName(rhsins.typ), newContext)
        }
      case st: SuInstance =>
        val newContext = st.loc match {
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
    if(inss.isEmpty) { // Just to make the flow continue
      val ins = sig.getReturnType.jawaName match {
        case "java.lang.String" => PTAPointStringInstance(context)
        case _ => PTAInstance(sig.getReturnType, context)
      }
      inss += ins
    }
    inss
  }

  def processLhs(
      sig: Signature,
      lhs: RuleLhs,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: ISet[RFAFact],
      context: Context): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    lhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(sig, thisSlot, st.heapOpt, recvOpt, args, input, context, isLhs = true)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num))
        slots = handleHeap(sig, argSlot, sa.heapOpt, recvOpt, args, input, context, isLhs = true)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(sig, gSlot, sg.heapOpt, recvOpt, args, input, context, isLhs = true)
      case sr: SuRet =>
        val retSlot = VarSlot(retOpt.getOrElse("hack"))
        slots = handleHeap(sig, retSlot, sr.heapOpt, recvOpt, args, input, context, isLhs = true)
    }
    slots
  }

  def handleHeap(
      sig: Signature,
      slot: NameSlot,
      heapOpt: Option[SuHeap],
      recvOpt: Option[String],
      args: IList[String],
      input: ISet[RFAFact],
      context: Context,
      isLhs: Boolean): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    heapOpt match {
      case Some(heap) =>
        var currentSlots: ISet[PTASlot] = Set(slot)
        heap.indices.foreach { heapAccess =>
          val facts = input.filter(i => currentSlots.contains(i.slot))
          heapAccess match {
            case fa: SuFieldAccess =>
              currentSlots = facts.map(fact => FieldSlot(fact.v, fa.fieldName))
            case _: SuArrayAccess =>
              currentSlots = facts.map(fact => ArraySlot(fact.v))
            case ma: SuMapAccess =>
              val inss: ISet[Instance] = facts.map(f => f.v)
              val keys: ISet[Instance] = ma.rhsOpt match {
                case Some(rhs) =>
                  val rhsInss = processRhs(sig, rhs, recvOpt, args, input, context)
                  if (isLhs) rhsInss
                  else {
                    val rhsTyps = rhsInss.map(i => i.typ)
                    input.filter(i =>
                      i.slot.isInstanceOf[MapSlot] &&
                        rhsTyps.contains(i.slot.asInstanceOf[MapSlot].key.typ)
                    ).map(i => i.slot.asInstanceOf[MapSlot].key)
                  }
                case None =>
                  input.filter(i =>
                    i.slot.isInstanceOf[MapSlot] &&
                      inss.contains(i.slot.asInstanceOf[MapSlot].ins)).map(i => i.slot.asInstanceOf[MapSlot].key)
              }
              currentSlots = inss.flatMap { ins =>
                keys.map { key =>
                  MapSlot(ins, key)
                }
              }
          }
        }
        slots ++= currentSlots
      case None => slots += slot
    }
    slots
  }
}