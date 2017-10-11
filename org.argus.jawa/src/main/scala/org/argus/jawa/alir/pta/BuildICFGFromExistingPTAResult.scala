/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg.{ICFGCallNode, ICFGInvokeNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.interprocedural.{CallHandler, Callee, InstanceCallee, StaticCallee}
import org.argus.jawa.core._
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
              val inss = pta_result.getPTSMap(icn.context).getOrElse(VarSlot(icn.argNames.head), isetEmpty)
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
                  inss.map {
                    case ins@un if un.isUnknown =>
                      val p = CallHandler.getUnknownVirtualCalleeMethods(global, un.typ, calleesig.getSubSignature)
                      calleeSet ++= p.map(callee => InstanceCallee(callee.getSignature, ins))
                    case ins =>
                      val p = CallHandler.getVirtualCalleeMethod(global, ins.typ, calleesig.getSubSignature)
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
