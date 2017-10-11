/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.wu

import org.argus.jawa.alir.cfg._
import org.argus.jawa.alir.dda.InterProceduralReachingDefinitionAnalysis.Node
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.rfa.SimHeap
import org.argus.jawa.alir.taintAnalysis.{SourceAndSinkManager, TaintNode}
import org.argus.jawa.ast.{CallStatement, ReturnStatement}
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.summary.store.{TSTaintPath, TaintStore}
import org.argus.jawa.summary.susaf.rule._
import org.argus.jawa.summary.{Summary, SummaryManager, SummaryRule}

class TaintWu[T <: Global](
    global: T,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T],
    ts: TaintStore)(implicit heap: SimHeap) extends DataFlowWu[T](global, method, sm, handler) {

  val srcInss: MSet[Instance] = msetEmpty
  val sinkInss: MSet[Instance] = msetEmpty

  override def parseIDFG(idfg: InterProceduralDataFlowGraph): IList[SummaryRule] = {
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

  override def processNode(node: ICFGNode, rules: MList[SummaryRule]): Unit = {
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
            for(i <- cs.rhs.argClause.varSymbols.indices) {
              res += Some(i)
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
                          Some(0)
                        case a: SuArg =>
                          if(cs.isStatic) {
                            Some(a.num)
                          } else {
                            Some(a.num + 1)
                          }
                        case _: SuGlobal =>
                          None
                        case _: SuRet =>
                          Some(-1)
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
        val size = (method.thisOpt ++ method.getParamNames).size
        val res: MSet[Option[Int]] = msetEmpty
        for(i <- 0 until size) {
          res += Some(i)
        }
        poss ++= res.toSet
      case _ => poss += None
    }
    poss foreach { pos =>
      val (srcs, sinks) = ssm.getSourceAndSinkNode(global, node, pos, ptaresult)
      ts.sourceNodes ++= srcs
      ts.sinkNodes ++= sinks
      val inss = getTaintCandidateInstances(node, pos)
      srcs foreach { src =>
        inss foreach { ins => ts.taintedInstance(ins) = List(src.node) }
      }
      sinks foreach { sink =>
        inss foreach { ins => ts.sinkDependence(ins) = List(sink.node) }
      }
      if(srcs.nonEmpty) {
        srcInss ++= inss
      }
      if(sinks.nonEmpty) {
        sinkInss ++= inss
      }
    }
    super.processNode(node, rules)
  }

  private def getTaintCandidateInstances(node: Node, pos: Option[Int]): ISet[Instance] = {
    node match {
      case ln: ICFGLocNode =>
        val l = method.getBody.resolvedBody.location(ln.locIndex)
        l.statement match {
          case cs: CallStatement =>
            val ns: NameSlot = pos match {
              case Some(i) =>
                if(i == -1) {
                  VarSlot(cs.lhsOpt.map(lhs => lhs.lhs.varName).getOrElse("hack"))
                } else {
                  val varName = if(cs.isStatic) {
                    cs.arg(i)
                  } else if(i == 0) {
                    cs.recvOpt.get
                  } else {
                    cs.arg(i - 1)
                  }
                  VarSlot(varName)
                }
              case None =>
                VarSlot(cs.lhsOpt.map(lhs => lhs.lhs.varName).getOrElse("hack"))
            }
            ptaresult.pointsToSet(node.getContext, ns)
          case _ =>
            isetEmpty
        }
      case _: ICFGEntryNode =>
        pos match {
          case Some(i) =>
            val args: IList[String] = (method.thisOpt ++ method.getParamNames).toList
            val ns: NameSlot = VarSlot(args.lift(i).getOrElse("hack"))
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
          if(path.size >= 2) {
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

case class TaintSummary(sig: Signature, rules: Seq[SummaryRule]) extends Summary
case class SourceSummaryRule(ins: Instance) extends SummaryRule
case class SinkSummaryRule(hb: HeapBase, ins: Instance) extends SummaryRule
trait TaintHeap
case class TaintField(name: String) extends TaintHeap
case class TaintArray() extends TaintHeap