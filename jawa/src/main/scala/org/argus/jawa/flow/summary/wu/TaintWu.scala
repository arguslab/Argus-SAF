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

import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dda.InterProceduralReachingDefinitionAnalysis.Node
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.taintAnalysis.{SSPosition, SourceAndSinkManager, TaintNode}
import org.argus.jawa.core.ast.{CallStatement, ReturnStatement}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.store.{TSTaintPath, TaintStore}
import org.argus.jawa.flow.summary.susaf.rule._
import org.argus.jawa.flow.summary.{Summary, SummaryManager, SummaryRule}

class TaintWu[T <: Global](
    global: T,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T],
    ts: TaintStore) extends DataFlowWu[T, TaintSummaryRule](global, method, sm, handler) {

  val srcInss: MSet[Instance] = msetEmpty
  val sinkInss: MSet[Instance] = msetEmpty

  override def parseIDFG(idfg: InterProceduralDataFlowGraph): IList[TaintSummaryRule] = {
    var rules = super.parseIDFG(idfg)
    // propagate source and sink
    var sources = srcInss.toSet
    val processed: MSet[Instance] = msetEmpty
    while(sources.nonEmpty) {
      processed ++= sources
      val newsources = propagateSource(sources)
      sources = newsources -- processed
      srcInss ++= sources
    }
    var sinks = sinkInss.toSet
    processed.clear()
    while(sinks.nonEmpty) {
      processed ++= sinks
      val newsinks = propagateSink(sinks)
      sinks = newsinks -- processed
      sinkInss ++= sinks
    }

    // Update SourceSummaryRule
    icfg.nodes foreach {
      case nn: ICFGNormalNode =>
        val l = method.getBody.resolvedBody.location(nn.locIndex)
        l.statement match {
          case rs: ReturnStatement =>
            rs.varOpt match {
              case Some(rv) =>
                val rvInss = ptaresult.pointsToSet(nn.getContext, VarSlot(rv.varName))
                val intersectInss = rvInss.intersect(srcInss)
                rules ++= intersectInss map (iins => SourceSummaryRule(iins))
              case None =>
            }
          case _ =>
        }
      case _ =>
    }
    srcInss foreach { srcIns =>
      heapMap.get(srcIns) match {
        case Some(_) =>
          rules +:= SourceSummaryRule(srcIns)
        case None =>
      }
    }
    // Update SinkSummaryRule
    sinkInss foreach { sinkIns =>
      heapMap.get(sinkIns) match {
        case Some(hb) =>
          rules +:= SinkSummaryRule(hb, sinkIns)
        case None =>
      }
    }
    rules
  }

  override def processNode(node: ICFGNode, rules: MList[TaintSummaryRule]): Unit = {
    val poss: MSet[Option[Int]] = msetEmpty
    node match {
      case in: ICFGInvokeNode =>
        val l = method.getBody.resolvedBody.location(in.locIndex)
        l.statement match {
          case cs: CallStatement =>
            val res: MSet[Option[Int]] = msetEmpty
            if(cs.lhsOpt.isDefined) {
              res += Some(-1)
            }
            val inc = if(cs.isStatic) 1 else 0
            for(i <- cs.rhs.varSymbols.indices) {
              res += Some(i + inc)
            }
            if(in.getCalleeSet.exists{ c =>
              val calleep = global.getMethodOrResolve(c.callee).get
              handler.isModelCall(calleep)
            }) {
              res += None
            }
            poss ++= res.toSet

            // Handle method calls with generated summary.
            val callees = in.getCalleeSet
            callees foreach { callee =>
              sm.getSummary[TaintSummary](callee.callee) match {
                case Some(summary) =>
                  summary.rules.foreach {
                    case SourceSummaryRule(ins) =>
                      srcInss += ins
                    case SinkSummaryRule(hb, oldIns) =>
                      val inss = getHeapInstance(hb, in.retNameOpt, cs.recvOpt, cs.arg, in.getContext)
                      sinkInss ++= inss
                      val pos = hb match {
                        case _: SuThis =>
                          Some(new SSPosition(0))
                        case a: SuArg =>
                          Some(new SSPosition(a.num))
                        case _: SuGlobal =>
                          None
                        case _: SuRet =>
                          Some(new SSPosition(-1))
                      }
                      inss foreach { ins => ts.sinkDependence(ins) = TaintNode(in, pos) :: ts.sinkDependence.getOrElse(oldIns, ilistEmpty)}
                    case _ =>
                  }
                case None =>
              }
            }
          case _ => poss += None
        }
      case _: ICFGEntryNode =>
        val res: MSet[Option[Int]] = msetEmpty
        method.thisOpt match {
          case Some(_) =>
            res += Some(0)
          case None =>
        }
        for(i <- 1 to method.getParamNames.size) {
          res += Some(i)
        }
        poss ++= res.toSet
      case _ => poss += None
    }
    poss foreach { pos =>
      val (srcs, sinks) = ssm.getSourceAndSinkNode(global, node, pos, ptaresult)
      ts.sourceNodes ++= srcs
      ts.sinkNodes ++= sinks
      if(srcs.nonEmpty) {
        srcs foreach { src =>
          val inss = getTaintCandidateInstances(node, src.node.pos)
          inss foreach { ins => ts.taintedInstance(ins) = List(src.node) }
          srcInss ++= inss
        }
      }
      if(sinks.nonEmpty) {
        sinks foreach { sink =>
          val inss = getTaintCandidateInstances(node, sink.node.pos)
          inss foreach { ins => ts.sinkDependence(ins) = List(sink.node)}
          sinkInss ++= inss
        }
      }
    }
    super.processNode(node, rules)
  }

  private def getTaintCandidateInstances(node: Node, pos: Option[SSPosition]): ISet[Instance] = {
    node match {
      case ln: ICFGLocNode =>
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        l.statement match {
          case cs: CallStatement =>
            pos match {
              case Some(i) =>
                if(i.pos == -1) {
                  val ns: NameSlot = VarSlot(cs.lhsOpt.map(lhs => lhs.name).getOrElse("hack"))
                  val fInss = ptaresult.getFieldInstances(node.getContext, ns, i.fields)
                  ptaresult.getRelatedInstances(node.getContext, fInss)
                } else {
                  val varName = if(cs.isStatic) {
                    cs.arg(i.pos - 1)
                  } else if(i.pos == 0) {
                    cs.recvOpt.get
                  } else {
                    cs.arg(i.pos - 1)
                  }
                  val ns: NameSlot = VarSlot(varName)
                  val fInss = ptaresult.getFieldInstancesAfterCall(node.getContext, ns, i.fields)
                  ptaresult.getRelatedInstancesAfterCall(node.getContext, fInss)
                }
              case None =>
                ptaresult.getRelatedInstances(node.getContext, VarSlot(cs.lhsOpt.map(lhs => lhs.name).getOrElse("hack")))
            }
          case _ =>
            isetEmpty
        }
      case _: ICFGEntryNode =>
        pos match {
          case Some(i) =>
            val args: IList[String] = (method.thisOpt ++ method.getParamNames).toList
            val ns: NameSlot = VarSlot(args.lift(i.pos).getOrElse("hack"))
            ptaresult.pointsToSet(node.getContext, ns)
          case None => isetEmpty
        }
      case _ => isetEmpty
    }
  }

  private def propagateSource(srcInss: ISet[Instance]): ISet[Instance] = {
    val newSources: MSet[Instance] = msetEmpty
    icfg.nodes foreach {
      case cn: ICFGCallNode =>
        val callees = cn.getCalleeSet
        if(callees exists { callee =>
          val method = global.getMethodOrResolve(callee.callee).get
          handler.scopeManager.shouldBypass(method.getDeclaringClass) && !handler.isConcreteModelCall(method)
        }) {
          for(i <- cn.argNames.indices) {
            val an = cn.argNames(i)
            val anInss = ptaresult.getRelatedInstances(cn.getContext, VarSlot(an))
            val intersectInss = anInss.intersect(srcInss)
            if(intersectInss.nonEmpty) {
              // Taint all other instances
              val allOtherInss: MSet[Instance] = msetEmpty
              cn.retNameOpt match {
                case Some(rn) =>
                  allOtherInss ++= ptaresult.pointsToSet(cn.getContext, VarSlot(rn))
                case None =>
              }
              for(j <- cn.argNames.indices) {
                if(i != j) {
                  val new_an = cn.argNames(j)
                  val new_anInss = ptaresult.getRelatedInstances(cn.getContext, VarSlot(new_an))
                  allOtherInss ++= new_anInss
                }
              }
              allOtherInss foreach { aoIns =>
                val list = ts.taintedInstance.getOrElseUpdate(aoIns, ilistEmpty)
                intersectInss foreach { iIns =>
                  ts.taintedInstance(aoIns) = ts.taintedInstance(iIns) ::: list
                }
              }
              newSources ++= allOtherInss
            }
          }
        }
      case _ =>
    }
    newSources.toSet
  }

  private def propagateSink(sinkInss: ISet[Instance]): ISet[Instance] = {
    val newSinks: MSet[Instance] = msetEmpty
    sinkInss foreach { sinkIns =>
      ts.tainted(sinkIns) match {
        case Some(list) =>
          val path = list ::: ts.sinkDependence.getOrElse(sinkIns, ilistEmpty)
          if(path.lengthCompare(2) >= 0) {
            ts.getSourceNode(path.head) match {
              case Some(sourceNode) =>
                ts.getSinkNode(path.last) match {
                  case Some(sinkNode) =>
                    ts.addTaintPath(new TSTaintPath(sourceNode, sinkNode, path))
                  case None =>
                }
              case None =>
            }
          }
        case None =>
          val defSite = sinkIns.defSite
          if(defSite.getMethodSig == method.getSignature) {
            if(!heapMap.contains(sinkIns)) {
              // Taint all other instances
              val allOtherInss: MSet[Instance] = msetEmpty
              val loc = method.getBody.resolvedBody.location(defSite.getCurrentLocUri)
              loc.statement match {
                case _: CallStatement =>
                  val cn: ICFGCallNode = icfg.getICFGCallNode(defSite).asInstanceOf[ICFGCallNode]
                  val callees = cn.getCalleeSet
                  if (callees exists { callee =>
                    val method = global.getMethodOrResolve(callee.callee).get
                    handler.scopeManager.shouldBypass(method.getDeclaringClass) && !handler.isConcreteModelCall(method)
                  }) {
                    for (i <- cn.argNames.indices) {
                      val an = cn.argNames(i)
                      val anInss = ptaresult.getRelatedInstances(cn.getContext, VarSlot(an))
                      allOtherInss ++= anInss
                    }
                  }
                case _ =>
              }
              allOtherInss foreach { aoIns =>
                val list = ts.sinkDependence.getOrElseUpdate(aoIns, ilistEmpty)
                ts.sinkDependence(aoIns) = ts.sinkDependence(sinkIns) ::: list
              }
              newSinks ++= allOtherInss
            }
          }
      }
    }
    newSinks.toSet
  }

  override def toString: String = s"TaintWu($method)"
}

case class TaintSummary(sig: Signature, rules: Seq[TaintSummaryRule]) extends Summary[TaintSummaryRule]
trait TaintSummaryRule extends SummaryRule
case class SourceSummaryRule(ins: Instance) extends TaintSummaryRule
case class SinkSummaryRule(hb: HeapBase, ins: Instance) extends TaintSummaryRule
trait TaintHeap
case class TaintField(name: String) extends TaintHeap
case class TaintArray() extends TaintHeap