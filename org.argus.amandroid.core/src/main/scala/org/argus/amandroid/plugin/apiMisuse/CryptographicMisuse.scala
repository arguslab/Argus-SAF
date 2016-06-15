/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
    val rule1Res = ECBCheck(global, nodeMap, ptaresult)
    val misusedApis: MMap[(Signature, String), String] = mmapEmpty
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          misusedApis((n.getContext.getMethodSig, n.getContext.getCurrentLocUri)) = "Using ECB mode!"
        }
    }
    ApiMisuseResult(misusedApis.toMap)
  }
  
  /**
   * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful, 
   * thus cannot be IND-CPA secure.
   */
  def ECBCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Boolean] = {
    var result: Map[ICFGCallNode, Boolean] = Map()
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
        val argNames: MList[String] = mlistEmpty
        loc match{
          case jumploc: JumpLocation =>
            jumploc.jump match {
              case t: CallJump if t.jump.isEmpty =>
                t.callExp.arg match {
                  case te: TupleExp =>
                    val exps = te.exps
                    for(i <- exps.indices) {
                      val varName = exps(i) match{
                        case ne: NameExp => ne.name.name
                        case a => a.toString
                      }
                      argNames += varName
                    }
                  case _ =>
                }
              case _ =>
            }
          case _ =>
        }
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
    result
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
//            val caller = global.getMethod(invNode.getOwner).get
//            val jumpLoc = caller.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
//            val cj = jumpLoc.jump.asInstanceOf[CallJump]
//            if(calleep.getSignature == Center.UNKNOWN_PROCEDURE_SIG){
//              val calleeSignature = cj.getValueAnnotation("signature") match {
//                case Some(s) => s match {
//                  case ne: NameExp => ne.name.name
//                  case _ => ""
//                }
//                case None => throw new RuntimeException("cannot found annotation 'signature' from: " + cj)
//              }
//              // source and sink APIs can only come from given app's parents.
//              callees ++= Center.getMethodDeclarations(calleeSignature)
//            } else {
              callees += calleep
//            }
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
}
