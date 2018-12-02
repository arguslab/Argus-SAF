/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.susaf

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.{RFAFact, ReachingFactsAnalysisHelper}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.SummaryManager
import org.argus.jawa.flow.summary.susaf.rule._

object HeapSummaryProcessor {
  def addDefaultTypes(global: Global, baseType: JawaType, types: IMap[String, JawaType]): Unit = {
    val baseClass: JawaClass = global.getClassOrResolve(baseType)
    types.foreach {
      case (name, typ) =>
        if(!baseClass.hasField(name)) {
          JawaField(baseClass, name, typ, 0)
        }
    }
  }

  def process(
      global: Global,
      sm: SummaryManager,
      sig: Signature,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: ISet[RFAFact],
      context: Context): ISet[RFAFact] = {
    sm.getSummary[HeapSummary](sig) match {
      case Some(hs) =>
        process(global, hs, retOpt, recvOpt, args, input, context)
      case _ =>
        input
    }
  }

  def process(
      global: Global,
      summary: HeapSummary,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: ISet[RFAFact],
      context: Context): ISet[RFAFact] = {
    var output: ISet[RFAFact] = ReachingFactsAnalysisHelper.aggregate(input)
    var kill: Boolean = false
    val extraFacts: MSet[RFAFact] = msetEmpty
    summary.rules foreach {
      case cr: ClearRule =>
        output = ReachingFactsAnalysisHelper.aggregate(output)
        val map = ReachingFactsAnalysisHelper.getFactMap(output)
        val slots = processLhs(global, summary.sig, cr.v, retOpt, recvOpt, args, map, extraFacts)
        val heaps = ReachingFactsAnalysisHelper.getRelatedHeapFactsFrom(output.filter(i => slots.contains(i.slot)), output)
        output --= heaps
        kill = true
      case br: BinaryRule =>
        output = ReachingFactsAnalysisHelper.aggregate(output)
        val map = ReachingFactsAnalysisHelper.getFactMap(output)
        val facts = processBinaryRule(global, summary.sig, br, retOpt, recvOpt, args, map, context, extraFacts)
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
    output ++= extraFacts
    if(kill) ReachingFactsAnalysisHelper.cleanHeap(output)
    else output
  }

  def processBinaryRule(
      global: Global,
      sig: Signature,
      br: BinaryRule,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: IMap[PTASlot, ISet[Instance]],
      context: Context,
      extraFacts: MSet[RFAFact]): ISet[RFAFact] = {
    val slots = processLhs(global, sig, br.lhs, retOpt, recvOpt, args, input, extraFacts)
    val isReturn = retOpt match {
      case Some(ret) => slots.exists(s => s.getId == ret)
      case None => false
    }
    val inss = processRhs(global, sig, br.rhs, retOpt, recvOpt, args, input, context, extraFacts, isReturn)
    slots.flatMap { slot =>
      inss.map(RFAFact(slot, _))
    }
  }

  def processRhs(
      global: Global,
      sig: Signature,
      rhs: RuleRhs,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: IMap[PTASlot, ISet[Instance]],
      context: Context,
      extraFacts: MSet[RFAFact],
      isReturn: Boolean): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    var slots: ISet[PTASlot] = isetEmpty
    rhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(global, sig, thisSlot, st.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sr: SuRet =>
        val retSlot = VarSlot(retOpt.getOrElse("hack"))
        slots = handleHeap(global, sig, retSlot, sr.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num - 1))
        slots = handleHeap(global, sig, argSlot, sa.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(global, sig, gSlot, sg.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sc: SuClassOf =>
        val newContext = sc.loc match {
          case scl: SuConcreteLocation =>
            context.copy.setContext(sig, scl.loc)
          case _: SuVirtualLocation =>
            context
        }
        val rhsInss = processRhs(global, sig, sc.rhs, retOpt, recvOpt, args, input, context, extraFacts, isReturn = false)
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
            Instance.getInstance(jt.typ, newContext, toUnknown = false)
          case st: SuString => PTAConcreteStringInstance(st.str, newContext)
        }
        inss += ins
    }
    inss ++= slots.flatMap(input.getOrElse(_, isetEmpty))
    if(inss.isEmpty) {
      slots.foreach {
        case hs: HeapSlot =>
          extraFacts ++= createHeapInstance(global, hs).map {i =>
            RFAFact(hs, i)
          }
          inss ++= extraFacts.filter(i => slots.contains(i.slot)).map(i => i.v)
        case _ =>
      }
    }
    inss
  }

  def processLhs(
      global: Global,
      sig: Signature,
      lhs: RuleLhs,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: IMap[PTASlot, ISet[Instance]],
      extraFacts: MSet[RFAFact]): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    lhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(global, sig, thisSlot, st.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num - 1))
        slots = handleHeap(global, sig, argSlot, sa.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(global, sig, gSlot, sg.heapOpt, retOpt, recvOpt, args, input, extraFacts)
      case sr: SuRet =>
        val rSlot = VarSlot(retOpt.getOrElse("hack"))
        slots = handleHeap(global, sig, rSlot, sr.heapOpt, retOpt, recvOpt, args, input, extraFacts)
    }
    slots
  }

  def handleHeap(
      global: Global,
      sig: Signature,
      slot: NameSlot,
      heapOpt: Option[SuHeap],
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: IMap[PTASlot, ISet[Instance]],
      extraFacts: MSet[RFAFact]): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    heapOpt match {
      case Some(heapAccess) =>
        var currentSlots: ISet[PTASlot] = Set(slot)
        heapAccess.indices.foreach { heapAccess =>
          var inss = currentSlots.flatMap(input.getOrElse(_, isetEmpty))
          if(inss.isEmpty) {
            currentSlots.foreach {
              case hs: HeapSlot =>
                extraFacts ++= createHeapInstance(global, hs).map {i =>
                  inss += i
                  RFAFact(hs, i)
                }
              case _ => // should not be here
            }
          }
          heapAccess match {
            case fa: SuFieldAccess =>
              currentSlots = inss.map(FieldSlot(_, fa.fieldName))
            case _: SuArrayAccess =>
              currentSlots = inss.map(ArraySlot)
          }
        }
        slots ++= currentSlots
      case None => slots += slot
    }
    slots
  }

  private def createHeapInstance(global: Global, hs: HeapSlot): Option[Instance] = {
    hs match {
      case fs: FieldSlot =>
        val baseClass = global.getClassOrResolve(fs.instance.typ)
        baseClass.getField(fs.fieldName) match {
          case Some(f) => Some(Instance.getInstance(f.getType, hs.instance.defSite, toUnknown = false))
          case None => Some(Instance.getInstance(JavaKnowledge.OBJECT, hs.instance.defSite, toUnknown = true))
        }
      case as: ArraySlot =>
        require(as.instance.typ.dimensions > 0, "Array type dimensions should larger than 0.")
        val typ = new JawaType(as.instance.typ.baseType, as.instance.typ.dimensions - 1)
        Some(Instance.getInstance(typ, as.instance.defSite, toUnknown = true))
      case _ => None // should not be here
    }
  }
}
