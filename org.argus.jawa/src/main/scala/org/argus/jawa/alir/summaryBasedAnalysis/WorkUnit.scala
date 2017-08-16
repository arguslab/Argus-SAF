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
        processAssignment(as, context, rules)
        updateHeapMap(as, context)
      case cs: CallStatement =>
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
            sm.getSummary(calleeSig) match {
              case Some(su) =>
                processSummary(su, cs.recvOpt, cs.arg, context, rules)
              case None =>

            }
          }
        }
      case rs: ReturnStatement =>
        rs.varOpt match {
          case Some(v) =>
            val inss = ptaresult.pointsToSet(context, VarSlot(v.varName))
            val bases = inss.flatMap(ins => heapMap.get(ins))
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
  }

  private def processAssignment(
      as: AssignmentStatement,
      context: Context,
      rules: MList[SuRule]) = {
    var inss: ISet[Instance] = isetEmpty
    var lhsBases: ISet[HeapBase] = isetEmpty
    as.lhs match {
      case ae: AccessExpression =>
        inss = ptaresult.pointsToSet(context, VarSlot(ae.varSymbol.varName))
        inss.foreach { ins =>
          heapMap.get(ins) match {
            case Some(hb) =>
              lhsBases += hb.make(Seq(SuFieldAccess(ae.fieldName)))
            case None =>
          }
        }
      case ie: IndexingExpression =>
        inss = ptaresult.pointsToSet(context, VarSlot(ie.varSymbol.varName))
        inss.foreach { ins =>
          heapMap.get(ins) match {
            case Some(hb) =>
              lhsBases += hb.make(Seq(SuArrayAccess()))
            case None =>
          }
        }
      case ne: NameExpression =>
        if(ne.isStatic) {
          inss = ptaresult.pointsToSet(context, StaticFieldSlot(ne.name))
          inss.foreach { ins =>
            heapMap.get(ins) match {
              case Some(hb) =>
                lhsBases += hb
              case None =>
            }
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
          case ne: NameExpression =>
            if(ne.isStatic) {
              inss = ptaresult.pointsToSet(context, StaticFieldSlot(ne.name))
            } else {
              inss = ptaresult.pointsToSet(context, VarSlot(ne.name))
            }
          case _ =>
        }
        val rhsBases: ISet[HeapBase] = inss.flatMap(ins => heapMap.get(ins))
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
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
    val summaries = sm.getSummaries(mc.safsuFile)
    summaries.get(signature.getSubSignature) match {
      case Some(summary) =>
        processSummary(summary, recvOpt, args, context, rules)
      case None =>
    }
  }

  private def processSummary(
      summary: Summary,
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
    summary.rules foreach {
      case cr: ClearRule =>
        handleClearRule(cr, recvOpt, args, context, rules)
      case br: BinaryRule =>
        handleBinaryRule(br, recvOpt, args, context, rules)
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
    val bases = inss.flatMap(ins => heapMap.get(ins))
    bases.headOption match {
      case Some(base) =>
        val heapAccesses: Seq[HeapAccess] = hb.heapOpt match {
          case Some(suHeap) =>
            suHeap.indices.map {
              case sm: SuMapAccess if sm.rhsOpt.isDefined =>
                SuMapAccess(handleRhs(sm.rhsOpt.get, recvOpt, args, context))
              case a => a
            }
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
        newBaseOpt = processVarSlot(VarSlot(args(sa.num)), hb, recvOpt, args, context)
      case g: SuGlobal =>
        newBaseOpt = Some(g)
      case _: SuRet =>
        newBaseOpt = None
    }
    newBaseOpt
  }

  private def getRhsInstance(
      rr: RuleRhs,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    rr match {
      case hb: HeapBase =>
        inss ++= getHeapInstance(hb, recvOpt, args, context)
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

  private def getHeapInstance(
      hb: HeapBase,
      recvOpt: Option[String],
      args: Int => String,
      context: Context): ISet[Instance] = {
    var inss: ISet[Instance] = isetEmpty
    hb match {
      case _: SuThis =>
        inss = ptaresult.pointsToSet(context, VarSlot(recvOpt.getOrElse("hack")))
      case a: SuArg =>
        inss = ptaresult.pointsToSet(context, VarSlot(args(a.num)))
      case g: SuGlobal =>
        inss = ptaresult.pointsToSet(context, StaticFieldSlot(g.fqn))
      case _: SuRet =>
    }
    hb.heapOpt match {
      case Some(h) =>
        h.indices.foreach {
          case sf: SuFieldAccess =>
            inss = inss.flatMap { ins =>
              ptaresult.pointsToSet(context, FieldSlot(ins, sf.fieldName))
            }
          case _: SuArrayAccess =>
            inss = inss.flatMap { ins =>
              ptaresult.pointsToSet(context, ArraySlot(ins))
            }
          case sm: SuMapAccess =>
            val keyInss: MSet[Instance] = msetEmpty
            sm.rhsOpt match {
              case Some(rhs) =>
                keyInss ++= getRhsInstance(rhs, recvOpt, args, context)
              case None =>
            }
            if(keyInss.isEmpty) {
              inss = ptaresult.getRelatedHeapInstances(context, inss)
            } else {
              inss = inss.flatMap { ins =>
                keyInss.flatMap { key =>
                  ptaresult.pointsToSet(context, MapSlot(ins, key))
                }
              }
            }
        }
      case None =>
    }
    inss
  }

  private def handleClearRule(
      cr: ClearRule,
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
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
      recvOpt: Option[String],
      args: Int => String,
      context: Context,
      rules: MList[SuRule]) = {
    handleLhs(br.lhs, recvOpt, args, context) match {
      case Some(lhs) =>
        handleRhs(br.rhs, recvOpt, args, context) match {
          case Some(rhs) =>
            rules += BinaryRule(lhs, br.ops, rhs)
          case None =>
            br.rhs match {
              case hb: HeapBase =>
                val hinss = getHeapInstance(hb, recvOpt, args, context)
                rules ++= hinss.map { ins =>
                  lhs match {
                    case hb: HeapBase =>
                      br.ops match {
                        case Ops.`+=` => heapMap(ins) = hb
                        case Ops.`=` => heapMap(ins) = hb
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

  override def toString: FileResourceUri = s"WorkUnit($method)"
}
