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
import org.argus.jawa.compiler.parser.{AssignmentStatement, CallStatement, NameExpression}
import org.argus.jawa.core.{Global, Signature}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class CryptographicMisuse extends ApiMisuseChecker {

  val name = "CryptographicMisuse"

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
    val misusedApis: MMap[(String, String), String] = mmapEmpty
    val rule1Res = ECBCheck(global, nodeMap, ptaresult)
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = "Using ECB mode!"
        }
    }
    val rule2Res = IVCheck(global, nodeMap, ptaresult)
    rule2Res.foreach {
      case (n, r) =>
        misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = r
    }
    ApiMisuseResult(name, misusedApis.toMap)
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
        val loc = global.getMethod(node.getOwner).get.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
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
  def IVCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, String] = {
    val result: MMap[ICFGCallNode, String] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstants.getIVParameterInitAPIs.contains(sig))
          nodes ++= ns
    }
    nodes.foreach{ node =>
      val loc = global.getMethod(node.getOwner).get.getBody.resolvedBody.locations(node.locIndex)
      val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
      require(argNames.isDefinedAt(0))
      val argSlot = VarSlot(argNames.head, isBase = false, isArg = true)
      val argValue = ptaresult.pointsToSet(argSlot, node.context)
      argValue.foreach {
        instance =>
          if(!instance.isUnknown) result += (node -> "Constant IV!")
          else {
            val defsite = instance.defSite
            val defloc = global.getMethod(defsite.getMethodSig).get.getBody.resolvedBody.location(defsite.getCurrentLocUri)
            defloc.statement match {
              case al: AssignmentStatement =>
                al.rhs match {
                  case ne: NameExpression =>
                    if(ne.isStatic) result += (node -> "Static IV!")
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
