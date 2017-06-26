/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.suspark

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dataFlowAnalysis.InterProceduralDataFlowGraph
import org.argus.jawa.alir.interprocedural.Callee
import org.argus.jawa.alir.pta.{Instance, PTAInstance, PTAScopeManager}
import org.argus.jawa.core._
import org.argus.jawa.core.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object InterProceduralSuperSpark {
  
  def apply(
      global: Global, 
      entryPoints: ISet[Signature]): InterProceduralDataFlowGraph = build(global, entryPoints)
  
  type N = ICFGNode
  
  def build(
      global: Global, 
      entryPoints: ISet[Signature]): InterProceduralDataFlowGraph = {
    val pag = new PointerAssignmentGraph[PtaNode]()
    val icfg = new InterProceduralControlFlowGraph[N]
    pta(global, pag, icfg, entryPoints)
    InterProceduralDataFlowGraph(icfg, pag.pointsToMap)
  }
  
  def pta(
      global: Global,
      pag: PointerAssignmentGraph[PtaNode],
      icfg: InterProceduralControlFlowGraph[N],
      entryPoints: ISet[Signature]): Unit = {
    entryPoints.foreach{ ep =>
      val epmopt = global.getMethod(ep)
      epmopt match {
        case Some(epm) =>
          if(epm.isConcrete)
            doPTA(global, epm, pag, icfg)
        case None =>
      }
    }
  }
  
  def doPTA(
      global: Global,
      ep: JawaMethod,
      pag: PointerAssignmentGraph[PtaNode],
      icfg: InterProceduralControlFlowGraph[N]): Unit = {
    val points = new PointsCollector().points(ep.getSignature, ep.getBody)
    val context: Context = new Context(global.projectName)
    pag.constructGraph(ep, points, context.copy, entryPoint = true)
    icfg.collectCfgToBaseGraph(ep, context.copy)
    workListPropagation(global, pag, icfg)
  }
  
  private def processStaticInfo(global: Global, pag: PointerAssignmentGraph[PtaNode], icfg: InterProceduralControlFlowGraph[N]) = {
    pag.processObjectAllocation()
    val staticCallees = pag.processStaticCall(global)
    staticCallees.foreach{
      case (pi, callee, context) =>
        var bypassFlag = false
        icfg.getCallGraph.addCall(pi.ownerSig, callee.callee)
        val clazz = global.getClassOrResolve(callee.callee.getClassType)
        if(!PTAScopeManager.shouldBypass(clazz)) {
          val calleeProc = clazz.getMethod(callee.callee.getSubSignature).get
          extendGraphWithConstructGraph(calleeProc, callee.pi, callee.node.getContext.copy, pag, icfg)
        } else {
          pag.handleModelCall(pi, context, callee)
          bypassFlag = true
        }
        val callNode = icfg.getICFGCallNode(callee.node.context).asInstanceOf[ICFGInvokeNode]
        callNode.addCallee(callee)
        val returnNode = icfg.getICFGReturnNode(callee.node.context).asInstanceOf[ICFGInvokeNode]
        returnNode.addCallee(callee)
        if(!bypassFlag) {
          icfg.deleteEdge(callNode, returnNode)
        }
    }
  }
  
  private def workListPropagation(
      global: Global,
      pag: PointerAssignmentGraph[PtaNode],
      icfg: InterProceduralControlFlowGraph[N]): Unit = {
    processStaticInfo(global, pag, icfg)
    while (pag.worklist.nonEmpty) {
      while (pag.worklist.nonEmpty) {
        val srcNode = pag.worklist.remove(0)
        srcNode.point match {
          case pbr: PointBaseR => // e.g. q = ofbnr.f; edge is ofbnr.f -> q
            val fp = pbr.getFieldPoint
            val fNode = pag.getNode(fp, srcNode.context)
            pag.successorEdges(fNode).foreach{
              edge => //edge is FIELD_LOAD type
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(fNode, dstNode)) pag.worklist += dstNode
                pag.pointsToMap.propagatePointsToSet(fNode, dstNode)
            }
          case _ =>
        }
        pag.successorEdges(srcNode).foreach{
          edge =>
            pag.getEdgeType(edge) match {
              case pag.EdgeType.TRANSFER => // e.g. L0: p = q; L1:  r = p; edge is p@L0 -> p@L1
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(srcNode, dstNode)) {
                  pag.worklist += dstNode
                  val d = pag.pointsToMap.getDiff(srcNode, dstNode)
                  pag.pointsToMap.transferPointsToSet(srcNode, dstNode)
                  checkAndDoCall(global, dstNode, d, pag, icfg)
                }
              case pag.EdgeType.THIS_TRANSFER => // e.g. L0: Call temp = foo(v1, v2); edge is v1@L0 -> foo.x@Lx
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(srcNode, dstNode)){
                  pag.worklist += dstNode
                  val d = pag.pointsToMap.getDiff(srcNode, dstNode) //TODO we can further refine this by filter only feasible instance to pass
                  pag.pointsToMap.transferPointsToSet(dstNode, d)
                }
              case pag.EdgeType.ASSIGNMENT => // e.g. q = p; Edge: p -> q
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(srcNode, dstNode)){
                  pag.worklist += dstNode
                  pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
                }
              case pag.EdgeType.FIELD_STORE => // e.g. r.f = q; Edge: q -> r.f
                val dstNode = pag.successor(edge)
                pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
              case pag.EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(srcNode, dstNode)){
                  pag.worklist += dstNode
                  pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
                }
              case pag.EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
                val dstNode = pag.successor(edge)
                if(!pag.pointsToMap.contained(srcNode, dstNode)){
                  pag.worklist += dstNode
                  pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
                }
              case pag.EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
                val dstNode = pag.successor(edge)
                if(pag.pointsToMap.isDiff(srcNode, dstNode)){
                  pag.worklist += dstNode
                  pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
                }
              case pag.EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
                val dstNode = pag.successor(edge)
                if(!pag.pointsToMap.contained(srcNode, dstNode)){
                  pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
                }
              case _ =>
            }
        }
      }
      pag.edges.foreach{
        edge =>
          pag.getEdgeType(edge) match{
            case pag.EdgeType.FIELD_STORE => // q -> r.f
              pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
            case pag.EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
              if(pag.pointsToMap.pointsToSet(edge.target).nonEmpty
                && !pag.pointsToMap.contained(edge.source, edge.target)){
                pag.worklist += edge.target
                pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
              }
            case pag.EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
              if(!pag.pointsToMap.contained(edge.source, edge.target)){
                pag.worklist += edge.target
                pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
              }
            case _ =>
          }
      }
      pag.edges.foreach{ edge =>
        pag.getEdgeType(edge) match{
          case pag.EdgeType.FIELD_LOAD => // p.f -> q
            if(pag.pointsToMap.pointsToSet(edge.source).isEmpty) {
              edge.source.point match {
                case fie: Point with Loc with Field =>
                  fie.fqn.typ match {
                    case obj if obj.isObject =>
                      val ins = PTAInstance(obj.toUnknown, edge.source.context)
                      edge.source.getSlots(pag.pointsToMap) foreach { slot =>
                        pag.pointsToMap.addInstance(pag.pointsToMap.heapContext, slot, ins)
                      }
                    case _ =>
                  }
                case _ =>
              }
            }
            if(pag.pointsToMap.isDiff(edge.source, edge.target)){
              pag.worklist += edge.target
              pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
            }
          case pag.EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
            if(pag.pointsToMap.isDiff(edge.source, edge.target)){
              pag.worklist += edge.target
              pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
            }
          case pag.EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
            if(pag.pointsToMap.pointsToSet(edge.source).isEmpty) {
              edge.source.point match {
                case fie: Point with Loc with Static_Field =>
                  fie.staticFieldFQN.typ match {
                    case obj if obj.isObject =>
                      val ins = PTAInstance(obj.toUnknown, edge.source.context)
                      edge.source.getSlots(pag.pointsToMap) foreach { slot =>
                        pag.pointsToMap.addInstance(pag.pointsToMap.heapContext, slot, ins)
                      }
                    case _ =>
                  }
                case _ =>
              }
            }
            if(pag.pointsToMap.isDiff(edge.source, edge.target)){
              pag.worklist += edge.target
              pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
            }
          case _ =>
        }
      }
    }
  }
  
  def checkAndDoCall(
      global: Global,
      node: PtaNode,
      d: ISet[Instance],
      pag: PointerAssignmentGraph[PtaNode],
      icfg: InterProceduralControlFlowGraph[N]): Unit = {
    val piOpt = pag.recvInverse(node)
    piOpt match {
      case Some(pi) =>
        val callerContext: Context = node.getContext
        val calleeSet: MSet[Callee] = msetEmpty
        if(pi.invokeTyp.equals("direct")){
          calleeSet ++= pag.getDirectCallee(global, d, pi)
        } else if(pi.invokeTyp.equals("super")){
          calleeSet ++= pag.getSuperCalleeSet(global, d, pi)
        } else {
          calleeSet ++= pag.getVirtualCalleeSet(global, d, pi)
        }
        var bypassflag = false
        calleeSet.foreach(
          callee => {
            icfg.getCallGraph.addCall(pi.ownerSig, callee.callee)
            val calleeProc = global.getMethod(callee.callee)
            if(calleeProc.isDefined && !PTAScopeManager.shouldBypass(calleeProc.get.getDeclaringClass) && calleeProc.get.isConcrete) {
              extendGraphWithConstructGraph(calleeProc.get, pi, callerContext.copy, pag, icfg)
            } else {
              pag.handleModelCall(pi, callerContext, callee)
              bypassflag = true
            }
          }
        )
        if(calleeSet.isEmpty) bypassflag = true
        val callNode = icfg.getICFGCallNode(callerContext).asInstanceOf[ICFGInvokeNode]
        callNode.addCallees(calleeSet.toSet)
        val returnNode = icfg.getICFGReturnNode(callerContext).asInstanceOf[ICFGInvokeNode]
        returnNode.addCallees(calleeSet.toSet)
        if(!bypassflag){
          icfg.deleteEdge(callNode, returnNode)
        }
        processStaticInfo(global, pag, icfg)
      case None =>
    }
  }
  
  def extendGraphWithConstructGraph(calleeProc: JawaMethod, 
      pi: Point with Invoke, 
      callerContext: Context,
      pag: PointerAssignmentGraph[PtaNode], 
      icfg: InterProceduralControlFlowGraph[N]): Unit = {
    val calleeSig = calleeProc.getSignature
    if(!pag.isProcessed(calleeSig, callerContext)){
      val points = new PointsCollector().points(calleeSig, calleeProc.getBody)
      pag.constructGraph(calleeProc, points, callerContext.copy, entryPoint = false)
      icfg.collectCfgToBaseGraph(calleeProc, callerContext.copy)
    }
    val methodPoint = pag.getPointMethod(calleeSig, callerContext)
    require(methodPoint != null)
    pag.extendGraph(methodPoint, pi, callerContext.copy)
    icfg.extendGraph(calleeSig, callerContext.copy)
  }
}
