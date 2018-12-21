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

import org.argus.jawa.core.ast.{AssignmentStatement, ReturnStatement, StaticFieldAccessExpression}
import org.argus.jawa.core.elements.{JavaKnowledge, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.summary.store.{TSTaintPath, TaintStore}
import org.argus.jawa.flow.summary.susaf.rule._
import org.argus.jawa.flow.summary.{Summary, SummaryManager, SummaryRule}
import org.argus.jawa.flow.taintAnalysis._

class TaintWu[T <: Global](
    global: T,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    ssm: SourceAndSinkManager[T],
    ts: TaintStore) extends DataFlowWu[T, TaintSummaryRule](global, method, sm, handler) {

  private def getTainted(cn: ICFGCallNode, poss: ISet[SSPosition], isSource: Boolean): ISet[Instance] = {
    if(poss.isEmpty) {
      val vars: MSet[String] = msetEmpty
      // Source means return value, sink means all poss
      if(isSource) {
        vars ++= cn.retNameOpt
      } else {
        vars ++= cn.argNames
      }
      vars.flatMap { v =>
        ptaresult.getRelatedInstances(cn.getContext, VarSlot(v)) ++ ptaresult.getRelatedInstancesAfterCall(cn.getContext, VarSlot(v))
      }.toSet
    } else {
      val inss: MSet[Instance] = msetEmpty
      poss.foreach { pos =>
        cn.argNames.lift(pos.pos - 1) match {
          case Some(name) =>
            val argInss = ptaresult.getRelatedInstances(cn.getContext, VarSlot(name)) ++ ptaresult.getRelatedInstancesAfterCall(cn.getContext, VarSlot(name))
            def getFieldInss(baseInss: ISet[Instance], fields: IList[String]): ISet[Instance] = {
              if(fields.isEmpty) return baseInss
              val field = fields.head
              var newInss = baseInss.flatMap { baseIns =>
                ptaresult.getRelatedInstances(cn.getContext, FieldSlot(baseIns, field)) ++ ptaresult.getRelatedInstancesAfterCall(cn.getContext, FieldSlot(baseIns, field))
              }
              if(newInss.isEmpty) {
                val typ = baseInss.head.typ
                val clazz = global.getClassOrResolve(typ)
                val ftype = clazz.getField(field) match {
                  case Some(f) => f.getType
                  case None => JavaKnowledge.OBJECT
                }
                baseInss.foreach { baseIns =>
                  val fins = Instance.getInstance(ftype, baseIns.defSite, toUnknown = true)
                  ptaresult.addInstance(cn.getContext, FieldSlot(baseIns, field), fins)
                  newInss += fins
                }
              }
              getFieldInss(newInss, fields.tail)
            }
            inss ++= getFieldInss(argInss, pos.fields)
          case None =>
        }
      }
      inss.toSet
    }
  }

  object TaintStatus extends Enumeration {
    val TAINT, FAKE, PASS = Value
  }

  case class TaintInfo(status: TaintStatus.Value, pos: Option[SSPosition], path: IList[TaintNode], kind: String)

  def getTaintInstance: ICFGNode => (IMap[Instance, TaintInfo], IMap[Instance, TaintInfo]) = {
    case en: ICFGEntryNode =>
      val srcInss: MMap[Instance, TaintInfo] = mmapEmpty
      en.thisName match {
        case Some(name) =>
          val inss = ptaresult.getRelatedInstances(en.getContext, VarSlot(name))
          val status = if(ssm.isEntryPointSource(global, en.getContext.getMethodSig)) {
            TaintStatus.TAINT
          } else {
            TaintStatus.PASS
          }
          val info = TaintInfo(status, Some(new SSPosition(0)), ilistEmpty, SourceAndSinkCategory.ENTRYPOINT_SOURCE)
          srcInss ++= inss.map(ins => (ins, info))
        case None =>
      }
      en.paramNames.indices foreach { idx =>
        val name = en.paramNames(idx)
        val inss = ptaresult.getRelatedInstances(en.getContext, VarSlot(name))
        val status = if(ssm.isEntryPointSource(global, en.getContext.getMethodSig) || ssm.isCallbackSource(global, en.getContext.getMethodSig, idx)) {
          TaintStatus.TAINT
        } else {
          TaintStatus.PASS
        }
        val info = TaintInfo(status, Some(new SSPosition(idx + 1)), ilistEmpty, SourceAndSinkCategory.ENTRYPOINT_SOURCE)
        srcInss ++= inss.map(ins => (ins, info))
      }
      (srcInss.toMap, imapEmpty)
    case cn: ICFGCallNode =>
      val srcInss: MMap[Instance, TaintInfo] = mmapEmpty
      val sinkInss: MMap[Instance, TaintInfo] = mmapEmpty
      // Handle method calls with generated summary.
      val callees = cn.getCalleeSet
      callees foreach { callee =>
        ssm.isSourceMethod(global, callee.callee) match {
          case Some((kind, poss)) =>
            val info = TaintInfo(TaintStatus.TAINT, None, ilistEmpty, kind)
            srcInss ++= getTainted(cn, poss, isSource = true).map(ins => (ins, info))
          case None =>
        }
        ssm.isSinkMethod(global, callee.callee) match {
          case Some((kind, poss)) =>
            val info = TaintInfo(TaintStatus.TAINT, None, ilistEmpty, kind)
            sinkInss ++= getTainted(cn, poss, isSource = false).map(ins => (ins, info))
          case None =>
        }
        sm.getSummary[TaintSummary](callee.callee) match {
          case Some(summary) =>
            summary.rules.foreach {
              case SourceSummaryRule(ins, kind, path) =>
                val info = TaintInfo(TaintStatus.FAKE, None, path, kind)
                srcInss += ((ins, info))
              case SinkSummaryRule(hb, kind, path) =>
                val inss = getHeapInstance(hb, cn.retNameOpt, cn.recvNameOpt, cn.argNames, cn.getContext)
                val info = TaintInfo(TaintStatus.FAKE, None, path, kind)
                sinkInss ++= inss.map(ins => (ins, info))
              case _ =>
            }
          case None =>
        }
      }
      (srcInss.toMap, sinkInss.toMap)
    case nn: ICFGNormalNode =>
      val srcInss: MMap[Instance, TaintInfo] = mmapEmpty
      val sinkInss: MMap[Instance, TaintInfo] = mmapEmpty
      val loc = method.getBody.resolvedBody.location(nn.locIndex)
      loc.statement match {
        case as: AssignmentStatement =>
          as.lhs match {
            case sfae: StaticFieldAccessExpression =>
              if(sfae.typ.isObject) {
                val inss = ptaresult.getRelatedInstances(nn.getContext, StaticFieldSlot(sfae.name))
                val info = TaintInfo(TaintStatus.PASS, None, ilistEmpty, SourceAndSinkCategory.STMT_SINK)
                sinkInss ++= inss.map(ins => (ins, info))
              }
            case _ =>
          }
          as.rhs match {
            case sfae: StaticFieldAccessExpression =>
              if(sfae.typ.isObject) {
                val inss = ptaresult.getRelatedInstances(nn.getContext, StaticFieldSlot(sfae.name))
                val info = TaintInfo(TaintStatus.PASS, None, ilistEmpty, SourceAndSinkCategory.STMT_SOURCE)
                srcInss ++= inss.map(ins => (ins, info))
              }
            case _ =>
          }
        case rs: ReturnStatement =>
          rs.varOpt match {
            case Some(ret) =>
              if (method.getReturnType.isObject) {
                val inss = ptaresult.getRelatedInstances(nn.getContext, VarSlot(ret.varName))
                val info = TaintInfo(TaintStatus.PASS, None, ilistEmpty, SourceAndSinkCategory.API_SINK)
                sinkInss ++= inss.map(ins => (ins, info))
              }
            case None =>
          }
        case _ =>
      }
      (srcInss.toMap, sinkInss.toMap)
    case en: ICFGExitNode =>
      val sinkInss: MMap[Instance, TaintInfo] = mmapEmpty
      en.thisName match {
        case Some(name) =>
          val thisInss = ptaresult.pointsToSet(en.getContext, VarSlot(name))
          val inss = ptaresult.getRelatedHeapInstances(en.getContext, thisInss)
          val info = TaintInfo(TaintStatus.PASS, Some(new SSPosition(0)), ilistEmpty, SourceAndSinkCategory.API_SINK)
          sinkInss ++= inss.map(ins => (ins, info))
        case None =>
      }
      en.paramNames.indices foreach { idx =>
        val name = en.paramNames(idx)
        val argInss = ptaresult.pointsToSet(en.getContext, VarSlot(name))
        val inss = ptaresult.getRelatedHeapInstances(en.getContext, argInss)
        val info = TaintInfo(TaintStatus.PASS, Some(new SSPosition(idx + 1)), ilistEmpty, SourceAndSinkCategory.API_SINK)
        sinkInss ++= inss.map(ins => (ins, info))
      }
      (imapEmpty, sinkInss.toMap)
    case _ =>
      (imapEmpty, imapEmpty)
  }

  def getAllInstances: ICFGNode => ISet[Instance] = {
    case cn: ICFGCallNode =>
      val allInss: MSet[Instance] = msetEmpty
      cn.retNameOpt match {
        case Some(rn) =>
          allInss ++= ptaresult.getRelatedInstancesAfterCall(cn.getContext, VarSlot(rn))
        case None =>
      }
      for (arg <- cn.allArgs) {
        allInss ++= ptaresult.getRelatedInstances(cn.getContext, VarSlot(arg)) ++ ptaresult.getRelatedInstancesAfterCall(cn.getContext, VarSlot(arg))
      }
      allInss.toSet
    case _ =>
      isetEmpty
  }

  override def parseIDFG(idfg: InterProceduralDataFlowGraph): IList[TaintSummaryRule] = {
    var rules = super.parseIDFG(idfg)

    val srcInstances: MSet[(Instance, String, IList[TaintNode])] = msetEmpty
    val sinkHeapBases: MSet[(HeapBase, String, IList[TaintNode])] = msetEmpty
    def dfs(node: ICFGNode, taintInss: IMap[Instance, TaintInfo], paths: IMap[Instance, IList[TaintNode]], processed: ISet[ICFGNode]): Unit = {
      var newPaths: IMap[Instance, IList[TaintNode]] = paths
      // handle pass through
      val allInss = getAllInstances(node)
      allInss.intersect(taintInss.keys.toSet).foreach { ins =>
        newPaths += (ins -> (newPaths.getOrElse(ins, ilistEmpty) :+ TaintNode(node, None)))
      }
      // handle source and sink
      val (srcInss, sinkInss) = getTaintInstance(node)
      sinkInss.foreach { case (sink, realsink) =>
        taintInss.get(sink) match {
          case Some(realsource) =>
            val sinkNode = TaintNode(node, realsink.pos)
            val path: IList[TaintNode] = paths(sink) :+ sinkNode
            val sourceNode = path.head
            realsource.status match {
              case TaintStatus.TAINT =>
                val taintSource = TaintSource(sourceNode, TypeTaintDescriptor(sourceNode.node.toString, realsource.pos, realsource.kind))
                realsink.status match {
                  case TaintStatus.TAINT =>
                    val taintSink = TaintSink(sinkNode, TypeTaintDescriptor(node.toString, realsink.pos, realsink.kind))
                    val tp = TSTaintPath(taintSource, taintSink)
                    tp.path = path
                    ts.addTaintPath(tp)
                  case TaintStatus.FAKE =>
                    val sinkPath = realsink.path
                    if(sinkPath.nonEmpty) {
                      val realSinkNode = sinkPath.last
                      val taintSink = TaintSink(realSinkNode, TypeTaintDescriptor(realSinkNode.node.toString, realSinkNode.pos, realsink.kind))
                      val tp = TSTaintPath(taintSource, taintSink)
                      tp.path = path ++ sinkPath
                      ts.addTaintPath(tp)
                    }
                  case TaintStatus.PASS =>
                    srcInstances += ((sink, realsource.kind, path))
                }
              case TaintStatus.FAKE =>
                val sourcePath = realsource.path
                if(sourcePath.nonEmpty) {
                  val realSourceNode = sourcePath.head
                  val taintSource = TaintSource(realSourceNode, TypeTaintDescriptor(realSourceNode.node.toString, realsource.pos, realsource.kind))
                  realsink.status match {
                    case TaintStatus.TAINT =>
                      val taintSink = TaintSink(sinkNode, TypeTaintDescriptor(node.toString, realsink.pos, realsink.kind))
                      val tp = TSTaintPath(taintSource, taintSink)
                      tp.path = sourcePath ++ path
                      ts.addTaintPath(tp)
                    case TaintStatus.FAKE =>
                      val sinkPath = realsink.path
                      if(sinkPath.nonEmpty) {
                        val realSinkNode = sinkPath.last
                        val taintSink = TaintSink(realSinkNode, TypeTaintDescriptor(realSinkNode.node.toString, realSinkNode.pos, realsink.kind))
                        val tp = TSTaintPath(taintSource, taintSink)
                        tp.path = sourcePath ++ path ++ sinkPath
                        ts.addTaintPath(tp)
                      }
                    case TaintStatus.PASS =>
                      srcInstances += ((sink, realsource.kind, sourcePath ++ path))
                  }
                }
              case TaintStatus.PASS =>
                realsink.status match {
                  case TaintStatus.TAINT =>
                    getInitialHeapBase(sink) match {
                      case Some(hb) =>
                        sinkHeapBases += ((hb, realsink.kind, path))
                      case None =>
                    }
                  case TaintStatus.FAKE =>
                    getInitialHeapBase(sink) match {
                      case Some(hb) =>
                        sinkHeapBases += ((hb, realsink.kind, path ++ realsink.path))
                      case None =>
                    }
                  case TaintStatus.PASS =>
                }
            }
          case None =>
        }
      }
      newPaths ++= srcInss.map { case (ins, info) =>
        val sourceNode = TaintNode(node, info.pos)
        info.status match {
          case TaintStatus.TAINT =>
            ins -> List(sourceNode)
          case TaintStatus.FAKE =>
            val sourcePath = info.path
            ins -> (sourcePath :+ sourceNode)
          case TaintStatus.PASS =>
            ins -> List(sourceNode)
        }
      }
      idfg.icfg.successors(node).foreach { succ =>
        if(!processed.contains(succ)) {
          dfs(succ, taintInss ++ srcInss, newPaths, processed + node)
        }
      }
    }

    // Update SourceSummaryRule
    dfs(idfg.icfg.entryNode, imapEmpty, imapEmpty, isetEmpty)
    srcInstances foreach { case (srcIns, kind, path) =>
      rules +:= SourceSummaryRule(srcIns, kind, path)
    }
    // Update SinkSummaryRule
    clearHeapBases(sinkHeapBases.toSet) foreach { case (hb, kind, path) =>
      rules +:= SinkSummaryRule(hb, kind, path)
    }
    rules
  }

  def clearHeapBases(heapBases: ISet[(HeapBase, String, IList[TaintNode])]): ISet[(HeapBase, String, IList[TaintNode])] = {
    var minHeapBases: ISet[HeapBase] = isetEmpty
    heapBases.foreach { case (hb, _, _) =>
      val size = minHeapBases.size
      minHeapBases = minHeapBases.filterNot { mhb =>
        mhb.toString.startsWith(hb.toString)
      }
      if(minHeapBases.isEmpty || minHeapBases.size < size) {
        minHeapBases += hb
      }
    }
    heapBases.filter{case (k, _, _) => minHeapBases.contains(k)}
  }

  override def toString: String = s"TaintWu($method)"
}

case class TaintSummary(sig: Signature, rules: Seq[TaintSummaryRule]) extends Summary[TaintSummaryRule] {
  override def toString: FileResourceUri = {
    val sb = new StringBuilder
    rules.foreach { rule =>
      sb.append(sig.signature)
      sb.append(" -> ")
      sb.append(rule.toString)
      sb.append("\n")
    }
    sb.toString().trim
  }
}
trait TaintSummaryRule extends SummaryRule
case class SourceSummaryRule(ins: Instance, kind: String, path: IList[TaintNode]) extends TaintSummaryRule {
  override def toString: FileResourceUri = "_SOURCE_"
}
case class SinkSummaryRule(hb: HeapBase, kind: String, path: IList[TaintNode]) extends TaintSummaryRule {
  override def toString: FileResourceUri = {
    val sb = new StringBuilder
    sb.append("_SINK_ ")
    hb match {
      case _: SuThis =>
        sb.append("this")
      case a: SuArg =>
        sb.append(a.num)
      case g: SuGlobal =>
        sb.append(g.fqn)
    }
    hb.heapOpt match {
      case Some(heap) =>
        sb.append(heap.toString)
      case None =>
    }
    sb.toString()
  }
}