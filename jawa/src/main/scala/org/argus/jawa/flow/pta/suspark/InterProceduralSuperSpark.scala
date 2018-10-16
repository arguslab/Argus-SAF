/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta.suspark

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGInvokeNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.interprocedural.{CallHandler, CallResolver, RFACallee}
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.flow.pta.{Instance, PTAInstance, PTAScopeManager}
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class InterProceduralSuperSpark(global: Global) {

  type N = ICFGNode

  private var pag: PointerAssignmentGraph[PtaNode] = _
  private var icfg: InterProceduralControlFlowGraph[N] = _
  
  def build(entryPoints: ISet[Signature]): InterProceduralDataFlowGraph = {
    pag = new PointerAssignmentGraph[PtaNode]()
    icfg = new InterProceduralControlFlowGraph[N]
    pta(entryPoints)
    InterProceduralDataFlowGraph(icfg, pag.pointsToMap)
  }
  
  def pta(entryPoints: ISet[Signature]): Unit = {
    entryPoints.foreach { ep =>
      val epmopt = global.getMethod(ep)
      epmopt match {
        case Some(epm) =>
          if(epm.isConcrete)
            doPTA(epm)
        case None =>
      }
    }
  }
  
  def doPTA(ep: JawaMethod): Unit = {
    val points = PointsCollector.points(ep.getSignature, ep.getBody)
    val context: Context = new Context(global.projectName)
    pag.constructGraph(ep, points, context.copy, entryPoint = true)
    icfg.collectCfgToBaseGraph(ep, context.copy, isFirst = true, needReturnNode = true)
    workListPropagation()
  }

  private def worklist1(): Unit = {
    val srcNode = pag.worklist.remove(0)
    srcNode.point match {
      case pbr: PointBaseR => // e.g. q = ofbnr.f; edge is ofbnr.f -> q
        val fp = pbr.getFieldPoint
        val fNode = pag.getNode(fp, srcNode.context)
        pag.successorEdges(fNode).foreach{ edge => //edge is FIELD_LOAD type
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(fNode, dstNode)) pag.worklist += dstNode
          pag.pointsToMap.propagatePointsToSet(fNode, dstNode)
        }
      case _ =>
    }
    pag.successorEdges(srcNode).foreach{ edge =>
      pag.getEdgeType(edge) match {
        case EdgeType.TRANSFER => // e.g. L0: p = q; L1:  r = p; edge is p@L0 -> p@L1
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(srcNode, dstNode)) {
            pag.worklist += dstNode
            val d = pag.pointsToMap.getDiff(srcNode, dstNode)
            pag.pointsToMap.transferPointsToSet(srcNode, dstNode)
            checkAndDoCall(dstNode, d)
          }
        case EdgeType.THIS_TRANSFER => // e.g. L0: Call temp = foo(v1, v2); edge is v1@L0 -> foo.x@Lx
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(srcNode, dstNode)){
            pag.worklist += dstNode
            val d = pag.pointsToMap.getDiff(srcNode, dstNode) // TODO we can further refine this by filter only feasible instance to pass
            pag.pointsToMap.transferPointsToSet(dstNode, d)
          }
        case EdgeType.ASSIGNMENT => // e.g. q = p; Edge: p -> q
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(srcNode, dstNode)){
            pag.worklist += dstNode
            pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
          }
        case EdgeType.FIELD_STORE => // e.g. r.f = q; Edge: q -> r.f
          val dstNode = pag.successor(edge)
          pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
        case EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(srcNode, dstNode)){
            pag.worklist += dstNode
            pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
          }
        case EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
          val dstNode = pag.successor(edge)
          if(!pag.pointsToMap.contained(srcNode, dstNode)){
            pag.worklist += dstNode
            pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
          }
        case EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
          val dstNode = pag.successor(edge)
          if(pag.pointsToMap.isDiff(srcNode, dstNode)){
            pag.worklist += dstNode
            pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
          }
        case EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
          val dstNode = pag.successor(edge)
          if(!pag.pointsToMap.contained(srcNode, dstNode)){
            pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
          }
        case _ =>
      }
    }
  }

  private def worklist2(): Unit = {
    pag.edges.foreach{ edge =>
      pag.getEdgeType(edge) match{
        case EdgeType.FIELD_STORE => // q -> r.f
          pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
        case EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
          if(pag.pointsToMap.pointsToSet(edge.target).nonEmpty
            && !pag.pointsToMap.contained(edge.source, edge.target)){
            pag.worklist += edge.target
            pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
          }
        case EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
          if(!pag.pointsToMap.contained(edge.source, edge.target)){
            pag.worklist += edge.target
            pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
          }
        case _ =>
      }
    }
    pag.edges.foreach { edge =>
      pag.getEdgeType(edge) match {
        case EdgeType.FIELD_LOAD => // p.f -> q
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
          if(pag.pointsToMap.isDiff(edge.source, edge.target)) {
            pag.worklist += edge.target
            pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
          }
        case EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
          if(pag.pointsToMap.isDiff(edge.source, edge.target)) {
            pag.worklist += edge.target
            pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
          }
        case EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
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
          if(pag.pointsToMap.isDiff(edge.source, edge.target)) {
            pag.worklist += edge.target
            pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
          }
        case _ =>
      }
    }
  }
  
  private def workListPropagation(): Unit = {
    pag.processObjectAllocation()
    pag.getStaticCallWithNoParam.foreach(n => checkAndDoCall(n, isetEmpty))
    while (pag.worklist.nonEmpty) { // Resolve field assign and store
      while (pag.worklist.nonEmpty) { // Resolve normal case
        worklist1()
      }
      worklist2()
    }
  }
  
  def checkAndDoCall(node: PtaNode, d: ISet[Instance]): Unit = {
    val piOpt = node.point match {
      case pc: Point with Arg with Call =>
        pag.updateArgPointInstances(pc, d)
        pag.updatePiTrackAndGet(pc)
      case pi: Point with Invoke =>
        Some(pi)
      case _ => None
    }
    piOpt match {
      case Some(pi) =>
        val callr = new DefaultCallr(pi)
        val callerNode = icfg.getICFGCallNode(node.context)
        global.getMethodOrResolve(callerNode.getOwner) match {
          case Some(method) =>
            method.getBody.resolvedBody.location(callerNode.getContext.getCurrentLocUri).statement match {
              case cs: CallStatement =>
                callr.resolveCall(isetEmpty, cs, callerNode)
              case _ =>
            }
          case None =>
        }
      case None =>
    }
  }

  class DefaultCallr(pi: Point with Invoke) extends CallResolver[ICFGNode, RFAFact] {
    /**
      * It returns the facts for each callee entry node and caller return node
      */
    def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: ICFGNode): (IMap[ICFGNode, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext: Context = callerNode.getContext
      val calleeSet: ISet[RFACallee] = CallHandler.getCalleeSet(global, cs, callerContext, pag.pointsToMap)
      var bypassflag = false
      calleeSet.foreach { callee =>
        icfg.getCallGraph.addCall(pi.ownerSig, callee.callee)
        val calleeProc = global.getMethod(callee.callee)
        if(calleeProc.isDefined && !PTAScopeManager.shouldBypass(calleeProc.get.getDeclaringClass) && calleeProc.get.isConcrete) {
          extendGraphWithConstructGraph(calleeProc.get, pi, callerContext.copy)
        } else {
          pag.handleModelCall(pi, callerContext, callee)
          bypassflag = true
        }
      }
      if(calleeSet.isEmpty) bypassflag = true
      val callNode = icfg.getICFGCallNode(callerContext).asInstanceOf[ICFGInvokeNode]
      callNode.addCallees(calleeSet.toSet)
      if(needReturnNode) {
        val returnNode = icfg.getICFGReturnNode(callerContext).asInstanceOf[ICFGInvokeNode]
        returnNode.addCallees(calleeSet.toSet)
        if (!bypassflag) {
          icfg.deleteEdge(callNode, returnNode)
        }
      }
      pag.processObjectAllocation()
      pag.getStaticCallWithNoParam.foreach(n => checkAndDoCall(n, isetEmpty))
      (imapEmpty, isetEmpty)
    }

    def extendGraphWithConstructGraph (
        calleeProc: JawaMethod,
        pi: Point with Invoke,
        callerContext: Context): Unit = {
      val calleeSig = calleeProc.getSignature
      if(!pag.isProcessed(calleeSig, callerContext)) {
        val points = PointsCollector.points(calleeSig, calleeProc.getBody)
        pag.constructGraph(calleeProc, points, callerContext, entryPoint = false)
        icfg.collectCfgToBaseGraph(calleeProc, callerContext, isFirst = false, needReturnNode = true)
      }
      val methodPoint = pag.getPointMethod(calleeSig, callerContext)
      require(methodPoint != null)
      pag.extendGraph(methodPoint, pi, callerContext)
      icfg.extendGraph(calleeSig, callerContext, needReturnNode = true)
    }

    def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGNode): ISet[RFAFact] = isetEmpty

    val needReturnNode: Boolean = true
  }
}
