/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGInvokeNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.interprocedural.{CallHandler, Callee, InstanceCallee, StaticCallee}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._

object BuildICFGFromExistingPTAResult {
  
  def apply(global: Global, pta_results: IMap[Signature, PTAResult]): IMap[JawaType, InterProceduralDataFlowGraph] = build(global, pta_results)
  
  type N = ICFGNode
  
  private def build(global: Global, pta_results: IMap[Signature, PTAResult]): IMap[JawaType, InterProceduralDataFlowGraph] = {
    val result: MMap[JawaType, InterProceduralDataFlowGraph] = mmapEmpty
    pta_results foreach {
      case (ep, pta_result) =>
        val icfg = new InterProceduralControlFlowGraph[N]
        val epmopt = global.getMethodOrResolve(ep)
        epmopt match {
          case Some(epm) => 
            if(epm.isConcrete) {
              doBuild(global, epm, icfg, pta_result)
              result(ep.getClassType) = InterProceduralDataFlowGraph(icfg, pta_result)
            }
          case None =>
        }
    }
    result.toMap
  }
  
  private def doBuild(
      global: Global,
      ep: JawaMethod,
      icfg: InterProceduralControlFlowGraph[N],
      pta_result: PTAResult): Unit = {
    val context: Context = new Context(global.projectName)
    val nodes = icfg.collectCfgToBaseGraph(ep, context, isFirst = true, needReturnNode = true)
    val worklist: MList[N] = mlistEmpty ++ nodes
    val processed: MSet[N] = msetEmpty
    while(worklist.nonEmpty) {
      val node = worklist.remove(0)
      node match {
        case icn: ICFGCallNode if !processed.contains(icn) =>
          val calleesig = icn.getCalleeSig
          val callType = icn.getCallType
          val calleeSet: MSet[Callee] = msetEmpty
          callType match {
            case "static" =>
              CallHandler.getStaticCalleeMethod(global, calleesig) match {
                case Some(callee) => calleeSet += StaticCallee(callee.getSignature)
                case None =>
              }
            case _ =>
              val inss = pta_result.getPTSMap(icn.context).getOrElse(VarSlot(icn.recvNameOpt.get), isetEmpty)
              callType match {
                case "direct" =>
                  CallHandler.getDirectCalleeMethod(global, calleesig) match {
                    case Some(callee) => calleeSet ++= inss.map(InstanceCallee(callee.getSignature, _))
                    case None =>
                  }
                case "super" =>
                  CallHandler.getSuperCalleeMethod(global, calleesig) match {
                    case Some(callee) => calleeSet ++= inss.map(InstanceCallee(callee.getSignature, _))
                    case None =>
                  }
                case "virtual" | _ =>
                  inss.map { ins =>
                    val p = CallHandler.getVirtualCalleeMethod(global, ins.typ, calleesig) match {
                      case Left(mopt) => mopt.toSet
                      case Right(methods) => methods
                    }
                    calleeSet ++= p.map(callee => InstanceCallee(callee.getSignature, ins))
                  }
              }
          }
          var bypassflag = false
          calleeSet.foreach{ callee =>
            icfg.getCallGraph.addCall(icn.getOwner, callee.callee)
            val calleeProc = global.getMethod(callee.callee)
            if(calleeProc.isDefined && !PTAScopeManager.shouldBypass(calleeProc.get.getDeclaringClass) && calleeProc.get.isConcrete) {
              worklist ++= extendGraphWithConstructGraph(calleeProc.get, icn.context.copy, icfg)
            } else {
              bypassflag = true
            }
          }
          if(calleeSet.isEmpty) bypassflag = true
          val callNode = icfg.getICFGCallNode(icn.context).asInstanceOf[ICFGInvokeNode]
          callNode.addCallees(calleeSet.toSet)
          val returnNode = icfg.getICFGReturnNode(icn.context).asInstanceOf[ICFGInvokeNode]
          returnNode.addCallees(calleeSet.toSet)
          if(!bypassflag){
            icfg.deleteEdge(callNode, returnNode)
          }
          processed += node
        case _ =>
      }
    }
  }
  
  private def extendGraphWithConstructGraph(calleeProc: JawaMethod, 
      callerContext: Context, 
      icfg: InterProceduralControlFlowGraph[N]): ISet[N] = {
    val nodes = icfg.collectCfgToBaseGraph(calleeProc, callerContext, isFirst = false, needReturnNode = true)
    icfg.extendGraph(calleeProc.getSignature, callerContext, needReturnNode = true)
    nodes
  }
}
