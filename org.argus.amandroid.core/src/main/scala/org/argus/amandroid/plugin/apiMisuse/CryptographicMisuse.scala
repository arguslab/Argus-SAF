/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.apiMisuse

import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult}
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGNode}
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.{PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.core.util.ASTUtil
import org.argus.jawa.core.{Global, Signature}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class CryptographicMisuse extends ApiMisuseChecker {

  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val idfg = idfgOpt.get
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    val nodeMap: MMap[String, MSet[ICFGCallNode]] = mmapEmpty
    icfg.nodes.foreach{
      node =>
        val result = getCryptoNode(global, node)
        result.foreach{
          r =>
            nodeMap.getOrElseUpdate(r._1, msetEmpty) += r._2
        }
    }
    val misusedApis: MMap[(Signature, String), String] = mmapEmpty
    val rule1Res = ECBCheck(global, nodeMap, ptaresult)
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          misusedApis((n.getContext.getMethodSig, n.getContext.getCurrentLocUri)) = "Using ECB mode!"
        }
    }
    val rule2Res = IVCheck(global, nodeMap, ptaresult)
    rule2Res.foreach {
      case (n, r) =>
        if(r.isDefined) {
          misusedApis((n.getContext.getMethodSig, n.getContext.getCurrentLocUri)) = r.get
        }
    }
    ApiMisuseResult(misusedApis.toMap)
  }

  def getCryptoNode(global: Global, node: ICFGNode): Set[(String, ICFGCallNode)] = {
    val result: MSet[(String, ICFGCallNode)] = msetEmpty
    node match{
      case invNode: ICFGCallNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{
          callee =>
            val calleep = callee.callee
            val callees: MSet[Signature] = msetEmpty
            callees += calleep
            callees.foreach{
              callee =>
                if(CryptographicConstants.getCryptoAPIs.contains(callee.signature)){
                  result += ((callee.signature, invNode))
                }
            }
        }
      case _ =>
    }
    result.toSet
  }
  
  /**
   * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful, 
   * thus cannot be IND-CPA secure.
   */
  def ECBCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Boolean] = {
    val result: MMap[ICFGCallNode, Boolean] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstants.getCipherGetinstanceAPIs.contains(sig))
          nodes ++= ns
    }
    nodes.foreach{
      node =>
        result += (node -> true)
        val loc = global.getMethod(node.getOwner).get.getBody.location(node.getLocIndex)
        val argNames: IList[String] = ASTUtil.getCallArgs(loc.asInstanceOf[JumpLocation])
        require(argNames.isDefinedAt(0))
        val argSlot = VarSlot(argNames.head, isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)
        argValue.foreach {
          case instance: PTAConcreteStringInstance =>
            if (CryptographicConstants.getECBSchemes.contains(instance.string))
              result += (node -> false)
          case _ =>
        }
    }
    result.toMap
  }

  /**
    * Rule 2 Do not use a non-random IV for CBC encryption.
    */
  def IVCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
    val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstants.getIVParameterInitAPIs.contains(sig))
          nodes ++= ns
    }
    nodes.foreach{
      node =>
        result += (node -> None)
        val loc = global.getMethod(node.getOwner).get.getBody.location(node.getLocIndex)
        val argNames: IList[String] = ASTUtil.getCallArgs(loc.asInstanceOf[JumpLocation])
        require(argNames.isDefinedAt(1))
        val argSlot = VarSlot(argNames(1), isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)
        argValue.foreach {
          instance =>
            if(!instance.isUnknown) result += (node -> Some("Constant IV!"))
            else {
              val defsite = instance.defSite
              val defloc = global.getMethod(defsite.getMethodSig).get.getBody.location(defsite.getCurrentLocUri)
              defloc match {
                case al: ActionLocation =>
                  al.action match {
                    case aa: AssignAction =>
                      if(ASTUtil.isStaticExp(aa.rhs)) {
                        result += (node -> Some("Static IV!"))
                      }
                    case _ =>
                  }
                case _ =>
              }
            }
        }
    }
    result.toMap
  }
}
