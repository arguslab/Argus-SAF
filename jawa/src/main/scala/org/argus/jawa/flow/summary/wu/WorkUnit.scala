/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.wu

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.interprocedural.ModelCallResolver
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.pta.rfa.{RFAFact, ReachingFactsAnalysis, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.ast._
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, Signature}
import org.argus.jawa.core.util.Property.Key
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.susaf.rule._
import org.argus.jawa.flow.summary.{Summary, SummaryManager, SummaryRule}

import scala.concurrent.duration._
import scala.language.postfixOps

trait WorkUnit[T <: Global] {
  val global: T
  val method: JawaMethod
  val sm: SummaryManager

  /**
    * Indicate whether heap summary is needed for this work unit. If needed, the HeapSummaryWu will run before hand.
    * @return boolean
    */
  def needHeapSummary: Boolean

  /**
    * Generate summary based on the specific work unit.
    * @param suGen summary generator.
    * @return generated Summary
    */
  def generateSummary(suGen: (Signature, IList[SummaryRule]) => Summary): Summary

  /**
    * Need process flag
    * @param handler model call handler
    * @return process flag
    */
  def needProcess(handler: ModelCallHandler): Boolean = true

  /**
    * Implement this function to do pre-analysis tasks
    */
  def initFn(): Unit = {}

  /**
    * Implement this function to do post-analysis tasks
    */
  def finalFn(): Unit = {}
}

abstract class DataFlowWu[T <: Global] (
    val global: T,
    val method: JawaMethod,
    val sm: SummaryManager,
    handler: ModelCallHandler) extends WorkUnit[T] {

  override def needProcess(handler: ModelCallHandler): Boolean = !handler.isModelCall(method)

  var resolve_static_init: Boolean = false

  // Summary based data-flow is context-insensitive
  Context.init_context_length(0)
  val initContext = new Context(global.projectName)

  var ptaresult: PTAResult = new PTAResult
  var icfg: InterProceduralControlFlowGraph[ICFGNode] = new InterProceduralControlFlowGraph[ICFGNode]
  var idfgOpt: Option[InterProceduralDataFlowGraph] = None
  def hasIDFG: Boolean = idfgOpt.isDefined
  def setIDFG(idfg: InterProceduralDataFlowGraph): Unit = {
    idfgOpt = Some(idfg)
    ptaresult = idfg.ptaresult
    icfg = idfg.icfg
    method.thisOpt match {
      case Some(_) =>
        val thisContext = initContext.copy
        thisContext.setContext(method.getSignature, "this")
        val ins = Instance.getInstance(method.getDeclaringClass.typ, thisContext, toUnknown = false)
        heapMap(ins) = SuThis(None)
      case None =>
    }
    method.params.indices.foreach { i =>
      val (_, typ) = method.params(i)
      if(typ.isObject) {
        val unknown = typ.jawaName match {
          case "java.lang.String" => false
          case _ => true
        }
        val argContext = initContext.copy
        argContext.setContext(method.getSignature, s"arg${i + 1}")
        val ins = Instance.getInstance(typ, argContext, unknown)
        heapMap(ins) = SuArg(i + 1, None)
      }
    }
  }
  def getIDFG: InterProceduralDataFlowGraph = {
    idfgOpt match {
      case Some(idfg) => idfg
      case None =>
        val idfg = generateIDFG_RFA
        setIDFG(idfg)
        idfg
    }
  }

  val heapMap: MMap[Instance, HeapBase] = mmapEmpty

  override def needHeapSummary: Boolean = true

  def generateSummary(suGen: (Signature, IList[SummaryRule]) => Summary): Summary = {
    val idfg = getIDFG
    suGen(method.getSignature, parseIDFG(idfg))
  }

  def generateIDFG_RFA: InterProceduralDataFlowGraph = {
    val analysis = new ReachingFactsAnalysis(global, icfg, ptaresult, handler, sm, new ClassLoadManager, resolve_static_init, Some(new MyTimeout(1 minutes)))
    val initialFacts: ISet[RFAFact] = {
      val result = msetEmpty[RFAFact]
      method.thisOpt match {
        case Some(t) =>
          val thisContext = initContext.copy
          thisContext.setContext(method.getSignature, "this")
          val ins = Instance.getInstance(method.getDeclaringClass.typ, thisContext, toUnknown = false)
          result += RFAFact(VarSlot(t), ins)
        case None =>
      }
      method.params.indices.foreach { i =>
        val (name, typ) = method.params(i)
        if(typ.isObject) {
          val unknown = typ.jawaName match {
            case "java.lang.String" => false
            case _ => true
          }
          val argContext = initContext.copy
          argContext.setContext(method.getSignature, s"arg${i + 1}")
          val ins = Instance.getInstance(typ, argContext, unknown)
          result += RFAFact(VarSlot(name), ins)
        }
      }
      result.toSet
    }
    analysis.process(method, initialFacts, initContext, new ModelCallResolver(global, ptaresult, icfg, sm, handler))
  }

  def parseIDFG(idfg: InterProceduralDataFlowGraph): IList[SummaryRule] = {
    val icfg = idfg.icfg
    val processed: MSet[ICFGNode] = msetEmpty
    val rules: MList[SummaryRule] = mlistEmpty
    val worklistAlgorithm = new WorklistAlgorithm[ICFGNode] {
      override def processElement(e: ICFGNode): Unit = {
        processed += e
        processNode(e, rules)
        worklist ++= icfg.successors(e) -- processed
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist :+= icfg.entryNode)
    rules.toList
  }

  /**
    * Overriding method need to invoke super to update the heap map properly.
    */
  def processNode(node: ICFGNode, rules: MList[SummaryRule]): Unit = {
    node match {
      case ln: ICFGLocNode =>
        val context = node.getContext
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        l.statement match {
          case as: AssignmentStatement =>
            updateHeapMap(as, context)
          case _ =>
        }
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
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        val inss = ptaresult.pointsToSet(context, slot)
        inss.foreach { ins =>
          if(ins.defSite == context) {
            heapMap(ins) = SuGlobal(sfae.name, None)
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
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        val inss = ptaresult.pointsToSet(context, slot)
        kill ++= inss
        inss.foreach { ins =>
          heapMap.get(ins) match {
            case Some(sh) =>
              heapBaseOpt = Some(sh)
            case None =>
              heapBaseOpt = Some(SuGlobal(sfae.name, None))
          }
        }
      case _ =>
    }
    val (gen, _) = ReachingFactsAnalysisHelper.processRHS(as.rhs, context, ptaresult)
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

  def getRhsInstance(
      rr: RuleRhs,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    rr match {
      case hb: HeapBase =>
        inss ++= getHeapInstance(hb, retOpt, recvOpt, args, context)
      case sc: SuClassOf =>
        val newContext = sc.loc match {
          case scl: SuConcreteLocation =>
            context.copy.setContext(method.getSignature, scl.loc)
          case _: SuVirtualLocation =>
            context
        }
        inss += PTAInstance(JavaKnowledge.CLASS, newContext)
      case si: SuInstance =>
        val newContext = si.loc match {
          case scl: SuConcreteLocation =>
            context.copy.setContext(method.getSignature, scl.loc)
          case _: SuVirtualLocation =>
            context
        }
        inss += PTAInstance(si.typ.typ, newContext)
    }
    inss
  }

  def getHeapInstance(
      hb: HeapBase,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context): ISet[Instance] = {
    val slot: PTASlot = hb match {
      case _: SuThis =>
        VarSlot(recvOpt.getOrElse("hack"))
      case a: SuArg =>
        VarSlot(args(a.num - 1))
      case g: SuGlobal =>
        StaticFieldSlot(g.fqn)
      case _: SuRet =>
        VarSlot(retOpt.getOrElse("hack"))
    }
    var inss: ISet[Instance] = ptaresult.pointsToSet(context, slot)
    hb.heapOpt match {
      case Some(h) =>
        inss = inss.flatMap(ins => getHeapInstanceFrom(ins, h.indices, retOpt, recvOpt, args, context))
      case None =>
    }
    inss
  }

  def getHeapInstanceFrom(
      baseInstance: Instance,
      heapAccesses: Seq[HeapAccess],
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context): ISet[Instance] = {
    var inss = Set(baseInstance)
    heapAccesses.foreach {
      case sf: SuFieldAccess =>
        inss = inss.flatMap { ins =>
          ptaresult.pointsToSet(context, FieldSlot(ins, sf.fieldName))
        }
      case _: SuArrayAccess =>
        inss = inss.flatMap { ins =>
          ptaresult.pointsToSet(context, ArraySlot(ins))
        }
    }
    inss
  }

  override def toString: String = s"DataFlowWu($method)"
}

case class PTSummary(sig: Signature, rules: Seq[SummaryRule]) extends Summary
case class PTSummaryRule(heapBase: HeapBase, point: (Context, PTASlot), trackHeap: Boolean) extends SummaryRule

class PTStore extends PropertyProvider {
  /**
    * supply property
    */
  val propertyMap: MLinkedMap[Key, Any] = mlinkedMapEmpty[Property.Key, Any]
  val resolved: PTAResult = new PTAResult
}

abstract class PointsToWu[T <: Global] (
    global: T,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    store: PTStore,
    key: String) extends DataFlowWu[T](global, method, sm, handler) {

  protected val pointsToResolve: MMap[Context, ISet[(PTASlot, Boolean)]] = mmapEmpty

  override def processNode(node: ICFGNode, rules: MList[SummaryRule]): Unit = {
    node match {
      case ln: ICFGLocNode =>
        val context = node.getContext
        // Handle newly added points for this context
        pointsToResolve.getOrElse(context, isetEmpty).foreach { case (slot, resolveHeap) =>
          val set = store.getPropertyOrElseUpdate[MSet[(Context, PTASlot)]](key, msetEmpty)
          set += ((context, slot))
          val map: IMap[PTASlot, ISet[Instance]] = if(resolveHeap) {
            ptaresult.getRelatedInstancesMap(context, slot)
          } else {
            Map(slot -> ptaresult.pointsToSet(context, slot))
          }
          map.foreach { case (s, inss) =>
            inss.foreach { ins =>
              heapMap.get(ins) match {
                case Some(hb) =>
                  rules += PTSummaryRule(hb, (context, s), resolveHeap)
                case None =>
                  store.resolved.addInstance(context, s, ins)
              }
              true // I don't know why I need this...
            }
          }
        }
        // Handle method calls with generated summary.
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        l.statement match {
          case cs: CallStatement =>
            val callees = node.asInstanceOf[ICFGInvokeNode].getCalleeSet
            callees foreach { callee =>
              sm.getSummary[PTSummary](callee.callee) match {
                case Some(summary) =>
                  summary.rules.foreach {
                    case ptr: PTSummaryRule =>
                      val hb = ptr.heapBase
                      val retOpt = cs.lhsOpt.map(lhs => lhs.name)
                      val (newhbs, inss) = processHeapBase(hb, retOpt, cs.recvOpt, cs.arg, context, ptr.trackHeap)
                      newhbs.foreach { case (s, nhbs) =>
                        var slot: PTASlot = s
                        s match {
                          case VarSlot(_) => slot = ptr.point._2
                          case _ =>
                        }
                        rules ++= nhbs.map(nhb => PTSummaryRule(nhb, (ptr.point._1, slot), ptr.trackHeap))
                      }
                      inss.foreach { case (s, is) =>
                        var slot: PTASlot = s
                        s match {
                          case VarSlot(_) => slot = ptr.point._2
                          case _ =>
                        }
                        store.resolved.addInstances(ptr.point._1, slot, is)
                      }
                    case _ =>
                  }
                case None =>
              }
            }
          case _ =>
        }
      case _ =>
    }
    super.processNode(node, rules)
  }

  private def processHeapBase(
      hb: HeapBase,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      resolveHeap: Boolean): (IMap[PTASlot, ISet[HeapBase]], IMap[PTASlot, ISet[Instance]]) = {
    val slot: PTASlot = hb match {
      case _: SuThis =>
        VarSlot(recvOpt.getOrElse("hack"))
      case a: SuArg =>
        VarSlot(args(a.num - 1))
      case g: SuGlobal =>
        StaticFieldSlot(g.fqn)
      case _: SuRet =>
        VarSlot(retOpt.getOrElse("hack"))
    }
    val newHeapBases: MMap[PTASlot, ISet[HeapBase]] = mmapEmpty
    val instances: MMap[PTASlot, ISet[Instance]] = mmapEmpty
    val map: IMap[PTASlot, ISet[Instance]] = if(resolveHeap) {
      ptaresult.getRelatedInstancesMap(context, slot)
    } else {
      Map(slot -> ptaresult.pointsToSet(context, slot))
    }
    map.foreach { case (s, inss) =>
      val newHbs: MSet[HeapBase] = msetEmpty
      val newIns: MSet[Instance] = msetEmpty
      inss.foreach { ins =>
        heapMap.get(ins) match {
          case Some(bhb) =>
            hb.heapOpt match {
              case Some(h) => newHbs += bhb.make(h.indices)
              case None => newHbs += bhb
            }
          case None =>
            hb.heapOpt match {
              case Some(h) => newIns ++= getHeapInstanceFrom(ins, h.indices, retOpt, recvOpt, args, context)
              case None => newIns += ins
            }
        }
      }
      newHeapBases(s) = newHbs.toSet
      instances(s) = newIns.toSet
    }
    (newHeapBases.toMap, instances.toMap)
  }
}