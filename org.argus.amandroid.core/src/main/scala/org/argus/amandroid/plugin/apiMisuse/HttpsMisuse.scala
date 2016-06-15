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

import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGNode}
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.core.{Global, Signature}
import org.sireum.pilar.ast._
import org.sireum.util._

/*
 * @author <a href="mailto:i@flanker017.me">Qidan He</a>
 */
object HttpsMisuse {
  private final val API_SIG = "Lorg/apache/http/conn/ssl/SSLSocketFactory;.setHostnameVerifier:(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V"
  private final val VUL_PARAM = "@@org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER"
  
  def apply(global: Global, idfg: InterproceduralDataFlowGraph): Unit
    = build(global, idfg)
    
  def build(global: Global, idfg: InterproceduralDataFlowGraph): Unit = {
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    val nodeMap: MMap[String, MSet[ICFGCallNode]] = mmapEmpty
//    val callmap = icfg.getCallGraph.getCallMap
    icfg.nodes.foreach{
      node =>
        val result = getHTTPSNode(global, node)
        result.foreach{
          r =>
            nodeMap.getOrElseUpdate(r._1, msetEmpty) += r._2
        }
    }
    val rule1Res = VerifierCheck(global, nodeMap, ptaresult)
    rule1Res.foreach{
      case (n, b) =>
        if(!b){
          println(n.context + " using wrong ssl hostname configuration!")
        }
    }
  }
  
  /**
   * detect constant propagation on ALLOW_ALLHOSTNAME_VERIFIER
   * which is a common api miuse in many android apps.
   */
  def VerifierCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): Map[ICFGCallNode, Boolean] = {
    var result: Map[ICFGCallNode, Boolean] = Map()
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(sig.equals(API_SIG))
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
        val argSlot = VarSlot(argNames(1), isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)
        argValue.foreach{
          ins =>
            val defsites = ins.defSite
            val loc = global.getMethod(defsites.getMethodSig).get.getBody.location(defsites.getCurrentLocUri)
            //The found definition loc should be an assignment action
            val bar:ActionLocation = loc.asInstanceOf[ActionLocation]
            val as:AssignAction = bar.action.asInstanceOf[AssignAction]
            //retrive right side value
            val nameExp:NameExp = as.rhs.asInstanceOf[NameExp]
            if(nameExp.name.name.equals(VUL_PARAM)) {
              result += (node -> false)
            }
        }
    }
    result
  }
  
  def getHTTPSNode(global: Global, node: ICFGNode): Set[(String, ICFGCallNode)] = {
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
//              callees ++= Center.getMethodDeclarations(calleeSignature)
//            } else {
              callees += calleep
//            }
            callees.foreach{
              callee =>
                if(callee.signature.equals(API_SIG)){
                  result += ((callee.signature, invNode))
                }
            }
        }
      case _ =>
    }
    result.toSet
  }
}
