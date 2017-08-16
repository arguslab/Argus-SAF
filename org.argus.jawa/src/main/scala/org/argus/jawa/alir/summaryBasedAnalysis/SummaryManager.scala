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

import com.google.common.base.Charsets
import com.google.common.io.Resources
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.parser.SummaryParser
import org.argus.jawa.summary.rule._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryManager(global: Global)(implicit heap: SimHeap) {

  //  Map from signature to Summary
  private val summaries: MMap[Signature, Summary] = mmapEmpty
  def register(signature: Signature, summary: Summary): Unit = summaries(signature) = summary
  def register(suCode: String): IMap[Signature, Summary] = {
    val su = SummaryParser(suCode)
    su.defaultTypes.foreach { case (baseType, fields) =>
      addDefaultTypes(baseType, fields)
    }
    this.summaries ++= su.summaries
    su.summaries
  }
  def getSummary(sig: Signature): Option[Summary] = summaries.get(sig)

  // Map from file name to sub signature to summary
  private var summaryFiles: IMap[String, IMap[String, Summary]] = imapEmpty
  // Internal use only
  def registerFileInternal(safsuPath: String): Unit = {
    val url = Resources.getResource(safsuPath)
    val code = Resources.toString(url, Charsets.UTF_8)
    val su = SummaryParser(code)
    su.defaultTypes.foreach { case (baseType, fields) =>
      addDefaultTypes(baseType, fields)
    }
    val s = su.summaries.map{case (k, v) => k.getSubSignature -> v}
    this.summaryFiles += FileUtil.filename(url.toString) -> s
  }

  /**
    * Using summary file name to get corresponding summaries.
    * @param fileName The file name like: String.safsu
    */
  def getSummaries(fileName: String): IMap[String, Summary] = {
    this.summaryFiles.getOrElse(fileName, imapEmpty)
  }

  def addDefaultTypes(baseType: JawaType, types: IMap[String, JawaType]): Unit = {
    val baseClass: JawaClass = global.getClassOrResolve(baseType)
    types.foreach {
      case (name, typ) =>
        baseClass.addField(JawaField(baseClass, name, typ, 0))
    }
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
    val extraFacts: MSet[RFAFact] = msetEmpty
    summary.rules foreach {
      case cr: ClearRule =>
        val slots = processLhs(summary.signature, cr.v, retOpt, recvOpt, args, output, context, extraFacts)
        val heaps = ReachingFactsAnalysisHelper.getRelatedHeapFactsFrom(output.filter(i => slots.contains(i.slot)), output)
        output --= heaps
        kill = true
      case br: BinaryRule =>
        val facts = processBinaryRule(summary.signature, br, retOpt, recvOpt, args, output, context, extraFacts)
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

  def processBinaryRule(sig: Signature, br: BinaryRule, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context, extraFacts: MSet[RFAFact]): ISet[RFAFact] = {
    val slots = processLhs(sig, br.lhs, retOpt, recvOpt, args, input, context, extraFacts)
    val isReturn = retOpt match {
      case Some(ret) => slots.exists(s => s.getId == ret)
      case None => false
    }
    val inss = processRhs(sig, br.rhs, retOpt, recvOpt, args, input, context, extraFacts, isReturn)
    slots.flatMap { slot =>
      inss.map { ins =>
        new RFAFact(slot, ins)
      }
    }
  }

  def processRhs(sig: Signature, rhs: RuleRhs, retOpt: Option[String], recvOpt: Option[String], args: IList[String], input: ISet[RFAFact], context: Context, extraFacts: MSet[RFAFact], isReturn: Boolean): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    var slots: ISet[PTASlot] = isetEmpty
    rhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(sig, thisSlot, st.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = false)
      case sr: SuRet =>
        val retSlot = VarSlot(retOpt.getOrElse("hack"))
        slots = handleHeap(sig, retSlot, sr.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = false)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num))
        slots = handleHeap(sig, argSlot, sa.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = false)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(sig, gSlot, sg.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = false)
      case sc: SuClassOf =>
        val newContext = sc.loc match {
          case scl: SuConcreteLocation =>
            context.copy.setContext(sig, scl.loc)
          case _: SuVirtualLocation =>
            context
        }
        val rhsInss = processRhs(sig, sc.rhs, retOpt, recvOpt, args, input, context, extraFacts, isReturn = false)
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
    inss ++= input.filter(i => slots.contains(i.slot)).map(i => i.v)
    if(inss.isEmpty) {
      slots.foreach {
        case hs: HeapSlot =>
          extraFacts ++= createHeapInstance(hs, context).map {i =>
            new RFAFact(hs, i)
          }
          inss ++= extraFacts.filter(i => slots.contains(i.slot)).map(i => i.v)
        case _ =>
      }
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
      context: Context,
      extraFacts: MSet[RFAFact]): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    lhs match {
      case st: SuThis =>
        val thisSlot = VarSlot(recvOpt.getOrElse("hack"))
        slots = handleHeap(sig, thisSlot, st.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = true)
      case sa: SuArg =>
        val argSlot = VarSlot(args(sa.num))
        slots = handleHeap(sig, argSlot, sa.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = true)
      case sg: SuGlobal =>
        val gSlot = StaticFieldSlot(sg.fqn)
        slots = handleHeap(sig, gSlot, sg.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = true)
      case sr: SuRet =>
        val rSlot = VarSlot(retOpt.getOrElse("hack"))
        slots = handleHeap(sig, rSlot, sr.heapOpt, retOpt, recvOpt, args, input, context, extraFacts, isLhs = true)
    }
    slots
  }

  def handleHeap(
      sig: Signature,
      slot: NameSlot,
      heapOpt: Option[SuHeap],
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      input: ISet[RFAFact],
      context: Context,
      extraFacts: MSet[RFAFact],
      isLhs: Boolean): ISet[PTASlot] = {
    var slots: ISet[PTASlot] = isetEmpty
    heapOpt match {
      case Some(heapAccess) =>
        var currentSlots: ISet[PTASlot] = Set(slot)
        heapAccess.indices.foreach { heapAccess =>
          var facts = input.filter(i => currentSlots.contains(i.slot))
          if(facts.isEmpty) {
            currentSlots.foreach {
              case hs: HeapSlot =>
                extraFacts ++= createHeapInstance(hs, context).map {i =>
                  new RFAFact(hs, i)
                }
              case _ => // should not be here
            }
            facts ++= extraFacts
          }
          heapAccess match {
            case fa: SuFieldAccess =>
              currentSlots = facts.map(fact => FieldSlot(fact.v, fa.fieldName))
            case _: SuArrayAccess =>
              currentSlots = facts.map(fact => ArraySlot(fact.v))
            case ma: SuMapAccess =>
              val inss: ISet[Instance] = facts.map(f => f.v)
              val keys: ISet[Instance] = ma.rhsOpt match {
                case Some(rhs) =>
                  val rhsInss = processRhs(sig, rhs, retOpt, recvOpt, args, input, context, extraFacts, isReturn = false)
                  if (isLhs) rhsInss
                  else {
                    val rhsTyps = rhsInss.map(i => i.typ)
                    var instances =
                      input.filter(i =>
                        i.slot.isInstanceOf[MapSlot] &&
                          rhsTyps.contains(i.slot.asInstanceOf[MapSlot].key.typ)
                      ).map(i => i.slot.asInstanceOf[MapSlot].key)
                    if(instances.isEmpty) { // try to find the key, if does not find, insert the key back to continue the flow.
                      rhsInss.foreach { i =>
                        inss.foreach{ ins =>
                          extraFacts += new RFAFact(FieldSlot(ins, "key"), i)
                          extraFacts += new RFAFact(MapSlot(ins, i), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, context))
                        }
                      }
                      instances = rhsInss
                    }
                    instances
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

  private def createHeapInstance(hs: HeapSlot, context: Context): Option[Instance] = {
    hs match {
      case fs: FieldSlot =>
        val baseClass = global.getClassOrResolve(fs.instance.typ)
        baseClass.getField(fs.fieldName) match {
          case Some(f) => Some(Instance.getInstance(f.getType, context, toUnknown = false))
          case None => Some(Instance.getInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, context, toUnknown = true))
        }
      case as: ArraySlot =>
        require(as.instance.typ.dimensions > 0, "Array type dimensions should larger than 0")
        val typ = JawaType(as.instance.typ.baseType, as.instance.typ.dimensions - 1)
        Some(Instance.getInstance(typ, context, toUnknown = true))
      case _: MapSlot =>
        Some(Instance.getInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, context, toUnknown = true))
      case _ => None // should not be here
    }
  }
}