/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dda

import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGExitNode, ICFGNormalNode}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.interprocedural.IndirectCallee
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.rda.{DefDesc, LocDefDesc, ParamDefDesc}
import org.argus.jawa.flow.AlirEdge
import org.argus.jawa.core.ast._
import org.argus.jawa.core.Global
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait InterProceduralDataDependenceInfo{
  def getIddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node]
  def getDependentPath(src: InterProceduralDataDependenceAnalysis.Node, dst: InterProceduralDataDependenceAnalysis.Node): IList[InterProceduralDataDependenceAnalysis.Edge]
  def isDependent(src: InterProceduralDataDependenceAnalysis.Node, dst: InterProceduralDataDependenceAnalysis.Node): Boolean
}

class DefaultInterProceduralDataDependenceInfo(iddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node]) extends InterProceduralDataDependenceInfo{
  def getIddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node] = iddg
  def getDependentPath(src: InterProceduralDataDependenceAnalysis.Node, dst: InterProceduralDataDependenceAnalysis.Node): IList[InterProceduralDataDependenceAnalysis.Edge] = {
    iddg.findPath(src, dst)
  }
  def isDependent(src: InterProceduralDataDependenceAnalysis.Node, dst: InterProceduralDataDependenceAnalysis.Node): Boolean = {
    getDependentPath(src, dst) != null
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
object InterProceduralDataDependenceAnalysis {
  final val TITLE = "InterProceduralDataDependenceAnalysis"
  type Node = IDDGNode
  type Edge = AlirEdge[Node]

  def apply(global: Global, idfg: InterProceduralDataFlowGraph): InterProceduralDataDependenceInfo = build(global, idfg)

  def build(global: Global, idfg: InterProceduralDataFlowGraph): InterProceduralDataDependenceInfo = {
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    val irdaResult = InterProceduralReachingDefinitionAnalysis(global, icfg)
    val iddg = new InterProceduralDataDependenceGraph[Node]
    iddg.initGraph(global, icfg)
    iddg.nodes.foreach { node =>
      val targetNodes: MSet[Node] = msetEmpty
      if(node != iddg.entryNode){
        node match {
          case en: IDDGEntryParamNode =>
            val icfgN = icfg.getICFGEntryNode(en.getContext)
            val icfgTarN = icfg.predecessors(icfgN)
            targetNodes ++= icfgTarN.map(n => iddg.findDefSite(n.getContext, en.position))
          case en: IDDGExitParamNode =>
            val icfgN = icfg.getICFGExitNode(en.getContext)
            val procName = en.paramName
            val irdaFacts = irdaResult(icfgN)
            targetNodes ++= searchRda(global, procName, en, irdaFacts, iddg)
          case cn: IDDGCallArgNode =>
            val icfgN = icfg.getICFGCallNode(cn.getContext)
            val irdaFacts = irdaResult(icfgN)
            targetNodes ++= processCallArg(global, cn, ptaresult, irdaFacts, iddg)
          case rn: IDDGReturnArgNode =>
            val icfgN = icfg.getICFGReturnNode(rn.getContext)
            val icfgTarN = icfg.predecessors(icfgN)
            icfgTarN.foreach {
              case cn: ICFGCallNode =>
                targetNodes += iddg.findDefSite(cn.getContext, rn.position)
              case en: ICFGExitNode =>
                if(!rn.getCalleeSet.exists(_.isInstanceOf[IndirectCallee])) {
                  targetNodes += iddg.findDefSite(en.getContext, rn.position)
                }
              case _ =>
            }
          case rn: IDDGReturnVarNode =>
            val icfgN = icfg.getICFGReturnNode(rn.getContext)
            val icfgTarN = icfg.predecessors(icfgN)
            icfgTarN.foreach {
              case cn: ICFGCallNode =>
                val retInss = ptaresult.pointsToSet(rn.getContext, VarSlot(rn.retVarName))
                val idEntNs = iddg.getIDDGCallArgNodes(cn).map(_.asInstanceOf[IDDGCallArgNode])
                if (retInss.isEmpty) targetNodes ++= idEntNs
                else {
                  val argInss = idEntNs.map { n =>
                    ptaresult.getRelatedInstances(n.getContext, VarSlot(n.argName))
                  }
                  val inc = if(cn.getCallType == "static") 1 else 0
                  val poss = retInss.flatMap { ins =>
                    argInss.filter(_.contains(ins)) map (ins => argInss.indexOf(ins) + inc)
                  }
                  if (poss.isEmpty) targetNodes ++= idEntNs
                  else {
                    targetNodes ++= poss.map(pos => iddg.findDefSite(cn.getContext, pos))
                  }
                }
              case en: ICFGExitNode =>
                val enPreds = icfg.predecessors(en)
                enPreds foreach {
                  case nn: ICFGNormalNode =>
                    targetNodes ++= iddg.findDefSite(nn.getContext)
                  case _ =>
                }
              case _ =>
            }
          case vn: IDDGVirtualBodyNode =>
            val icfgN = vn.icfgN
            val idEntNs = iddg.getIDDGCallArgNodes(icfgN)
            targetNodes ++= idEntNs
            val irdaFacts = irdaResult(icfgN)
            targetNodes ++= processVirtualBody(global, vn, ptaresult, irdaFacts, iddg)
          case ln: IDDGNormalNode =>
            val icfgN = icfg.getICFGNormalNode(ln.getContext)
            global.getMethod(ln.getOwner) match {
              case Some(ownerProc) =>
                val loc = ownerProc.getBody.resolvedBody.locations(ln.getLocIndex)
                val irdaFacts = irdaResult(icfgN)
                targetNodes ++= processLocation(global, node, loc, ptaresult, irdaFacts, iddg)
              case None =>
            }
          case _ =>
        }
      }
      targetNodes.foreach(tn=>iddg.addEdge(node, tn))
    }
    global.reporter.echo(NoPosition, "[IDDG building done!]")
    new DefaultInterProceduralDataDependenceInfo(iddg)
  }
  
  def processCallArg(
      global: Global,
      callArgNode: IDDGCallArgNode,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    result ++= searchRda(global, callArgNode.argName, callArgNode, irdaFacts, iddg)
    val argSlot = VarSlot(callArgNode.argName)
    val inss = ptaresult.pointsToSet(callArgNode.getContext, argSlot)
    inss.foreach(ins => result ++= iddg.findDefSite(ins.defSite))
    result.toSet
  }
  
  def processVirtualBody(
      global: Global,
      virtualBodyNode: IDDGVirtualBodyNode,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    val calleeSet = virtualBodyNode.getCalleeSet
    calleeSet.foreach{ callee =>
      val calleeSig = callee.callee
      if(global.isSystemLibraryClasses(calleeSig.getClassType) || global.isUserLibraryClasses(calleeSig.getClassType)) {
//        val sideEffectResult =
//          if(LibSideEffectProvider.isDefined) LibSideEffectProvider.ipsear.result(calleeSig)
//          else None
        for(i <- virtualBodyNode.argNames.indices) {
          val argSlot = VarSlot(virtualBodyNode.argNames(i))
          val argInss = ptaresult.pointsToSet(virtualBodyNode.getContext, argSlot)
          argInss.foreach (ins => result ++= iddg.findDefSite(ins.defSite))
//          if(sideEffectResult.isDefined) {
//              val readmap = sideEffectResult.get.readMap
//              val position = i
//              val fields = readmap.getOrElse(position, Set())
//              argInss.foreach{ argIns =>
//                fields.foreach{ f =>
//                  val fs = FieldSlot(argIns, f)
//                  val argRelatedValue = ptaresult.getRelatedInstances(fs, virtualBodyNode.getContext)
//                  argRelatedValue.foreach{ins => result ++= iddg.findDefSite(ins.defSite)}
//                }
//              }
//          } else if({
//            val calleep = global.getMethod(calleeSig)
//            if(calleep.isDefined) calleep.get.isConcrete
//            else false
//          }) {
//              val argRelatedValue = ptaresult.getRelatedHeapInstances(argInss, virtualBodyNode.getContext)
//              argRelatedValue.foreach{
//                ins =>
//                  result ++= iddg.findDefSite(ins.defSite)
//              }
//          }
        }
      }
    }
    result.toSet
  }

  def processLocation(
      global: Global,
      node: Node,
      loc: Location,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    loc.statement match{
      case as: AssignmentStatement =>
        val lhs = as.lhs
        val rhs = as.rhs
        result ++= processLHS(global, node, lhs, ptaresult, irdaFacts, iddg)
        result ++= processRHS(global, node, rhs, ptaresult, irdaFacts, iddg)
      case rs: ReturnStatement =>
        if (rs.varOpt.isDefined) {
          result ++= searchRda(global, rs.varOpt.get.varName, node, irdaFacts, iddg)
          val slot = VarSlot(rs.varOpt.get.varName)
          val value = ptaresult.pointsToSet(node.getContext, slot)
          value.foreach{ ins =>
            result ++= iddg.findDefSite(ins.defSite)
          }
        }
      case is: IfStatement =>
        result ++= processCondition(global, node, is.cond, ptaresult, irdaFacts, iddg)
      case ss: SwitchStatement =>
        result ++= processVar(global, node, ss.condition.varName, ptaresult, irdaFacts, iddg)
      case ms: MonitorStatement =>
        result ++= processVar(global, node, ms.varSymbol.varName, ptaresult, irdaFacts, iddg)
      case ts: ThrowStatement =>
        result ++= processVar(global, node, ts.varSymbol.varName, ptaresult, irdaFacts, iddg)
      case _ =>
    }
    result.toSet
  }

  def processLHS(
      global: Global,
      node: Node,
      lhs: Expression with LHS,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    var result = isetEmpty[Node]
    lhs match {
      case ae: AccessExpression =>
        result ++= searchRda(global, ae.base, node, irdaFacts, iddg)
      case ie: IndexingExpression =>
        result ++= searchRda(global, ie.base, node, irdaFacts, iddg)
      case _ =>
    }
    result
  }

  def processRHS(
      global: Global,
      node: Node,
      rhs: Expression with RHS,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    rhs match {
      case vne: VariableNameExpression =>
        result ++= searchRda(global, vne.name, node, irdaFacts, iddg)
        val slot = VarSlot(vne.name)
        val value = ptaresult.pointsToSet(node.getContext, slot)
        value.foreach{ ins =>
          result ++= iddg.findDefSite(ins.defSite)
        }
      case sfae: StaticFieldAccessExpression =>
        result ++= searchRda(global, sfae.name, node, irdaFacts, iddg)
        val slot = StaticFieldSlot(sfae.name)
        val value = ptaresult.pointsToSet(node.getContext, slot)
        value.foreach{ ins =>
          result ++= iddg.findDefSite(ins.defSite)
        }
      case ae: AccessExpression =>
        result ++= searchRda(global, ae.base, node, irdaFacts, iddg)
        val baseSlot = VarSlot(ae.base)
        val baseValue = ptaresult.pointsToSet(node.getContext, baseSlot)
        baseValue.foreach{ ins =>
          result ++= iddg.findDefSite(ins.defSite)
          if(!ins.isNull) {
            val fieldSlot = FieldSlot(ins, ae.fieldName)
            val fieldValue = ptaresult.pointsToSet(node.getContext, fieldSlot)
            fieldValue.foreach(fIns => result ++= iddg.findDefSite(fIns.defSite))
          }
        }
      case ie: IndexingExpression =>
        result ++= searchRda(global, ie.base, node, irdaFacts, iddg)
        val baseSlot = VarSlot(ie.base)
        val baseValue = ptaresult.pointsToSet(node.getContext, baseSlot)
        baseValue.foreach{ ins =>
          result ++= iddg.findDefSite(ins.defSite)
          val arraySlot = ArraySlot(ins)
          val arrayValue = ptaresult.getRelatedInstances(node.getContext, arraySlot)
          arrayValue.foreach(aIns => result ++= iddg.findDefSite(aIns.defSite))
        }
      case ce: CastExpression =>
        result ++= searchRda(global, ce.varName, node, irdaFacts, iddg)
        val slot = VarSlot(ce.varName)
        val value = ptaresult.pointsToSet(node.getContext, slot)
        value.foreach { ins =>
          val defSite = ins.defSite
          result ++= iddg.findDefSite(defSite)
        }
      case _=>
    }
    result.toSet
  }

  private def processCondition(
      global: Global,
      node: Node,
      cond: BinaryExpression,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    result ++= processVar(global, node, cond.left.varName, ptaresult, irdaFacts, iddg)
    cond.right match {
      case Left(v) =>
        result ++= processVar(global, node, v.varName, ptaresult, irdaFacts, iddg)
      case Right(_) =>
    }
    result.toSet
  }

  private def processVar(
      global: Global,
      node: Node,
      varName: String,
      ptaresult: PTAResult,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    val result = msetEmpty[Node]
    result ++= searchRda(global, varName, node, irdaFacts, iddg)
    val slot = VarSlot(varName)
    val value = ptaresult.pointsToSet(node.getContext, slot)
    value.foreach{ ins =>
      result ++= iddg.findDefSite(ins.defSite)
    }
    result.toSet
  }

  def searchRda(
      global: Global,
      varName: String,
      node: Node,
      irdaFacts: ISet[InterProceduralReachingDefinitionAnalysis.IRDFact],
      iddg: InterProceduralDataDependenceGraph[Node]): ISet[Node] = {
    var result: ISet[Node] = isetEmpty
    val varN = varName
    irdaFacts.foreach {
      case ((slot, defDesc), tarContext) => 
        if(varN == slot.toString) {
          defDesc match {
            case _: ParamDefDesc =>
              result ++= iddg.findVirtualBodyDefSite(tarContext)
            case _: LocDefDesc =>
              result ++= iddg.findDefSite(tarContext, isRet = true)
            case dd: DefDesc =>
              if(dd.isDefinedInitially && !varName.startsWith("@@")){
                val indexs: MSet[Int] = msetEmpty
                val owner = global.getMethod(node.getOwner).get
                owner.thisOpt foreach{ t =>
                  if(t == varName) indexs += 0
                }
                val paramNames = owner.getParamNames
                for(i <- paramNames.indices){
                  val paramName = paramNames(i)
                  if(paramName == varName) indexs += i + 1
                }
                result ++= indexs.map(i => iddg.findDefSite(tarContext, i))
              }
          }
        }
    }
    result
  }

}
