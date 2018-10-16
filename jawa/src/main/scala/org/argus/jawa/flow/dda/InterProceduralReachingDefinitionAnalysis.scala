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

import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dfa._
import org.argus.jawa.flow.interprocedural.CallResolver
import org.argus.jawa.flow.rda._
import org.argus.jawa.flow.{Context, JawaAlirInfoProvider}
import org.argus.jawa.core.ast.{AssignmentStatement, CallStatement, Statement}
import org.argus.jawa.core.Global
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object InterProceduralReachingDefinitionAnalysis {
  type RDFact = ReachingDefinitionAnalysis.RDFact
  type LOC = Context
  type IRDFact = (RDFact, LOC)
  type Node = ICFGNode

  def apply(
      global: Global,
      cg: InterProceduralControlFlowGraph[Node]): MIdMap[Node, ISet[IRDFact]] = build(global, cg)

  def build(
      global: Global,
      cg: InterProceduralControlFlowGraph[Node]): MIdMap[Node, ISet[IRDFact]] = {
    new InterProceduralReachingDefinitionAnalysis().build(global, cg)
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class InterProceduralReachingDefinitionAnalysis {
  import InterProceduralReachingDefinitionAnalysis._
  
  var icfg: InterProceduralControlFlowGraph[Node] = _
  var factSet: MIdMap[Node, ISet[IRDFact]] = idmapEmpty[Node, ISet[IRDFact]]
  
  def build(
      global: Global,
      icfg: InterProceduralControlFlowGraph[Node]): MIdMap[Node, ISet[IRDFact]] = {
    val gen = new Gen
    val kill = new Kill
    val callr = Some(new Callr)
    val ip = new InterIngredientProvider[IRDFact](global, icfg)
    this.icfg = icfg
    icfg.nodes.foreach{ node =>
      global.getMethod(node.getOwner) match {
        case Some(owner) =>
          if(!owner.isUnknown){
            val cfg = JawaAlirInfoProvider.getCfg(owner)
            val rda = JawaAlirInfoProvider.getRdaWithCall(owner, cfg)
            node match{
              case cvn: ICFGVirtualNode =>
                val rdafact = rda.entrySet(cfg.getVirtualNode(cvn.getVirtualLabel))
                factSet.update(cvn, rdafact.map{fact => (fact, getContext(fact, cvn.getContext))})
              case cln: ICFGLocNode =>
                val rdafact = rda.entrySet(cfg.getNode(owner.getBody.resolvedBody.locations(cln.locIndex)))
                factSet.update(cln, rdafact.map{fact => (fact, getContext(fact, cln.getContext))})
            }
          }
        case None =>
      }

    }
    val initialContext: Context = new Context(global.projectName)
    val iota: ISet[IRDFact] = isetEmpty + (((VarSlot("@@IRDA"), InitDefDesc), initialContext))
    val initial: ISet[IRDFact] = isetEmpty
    MonotoneDataFlowAnalysisFramework[Node, IRDFact, LOC](icfg,
      forward = true, lub = true, ip, gen, kill, callr, iota, initial)
    factSet
  }
  
  private def getContext(fact: RDFact, srcContext: Context): Context = {
    val procSig = srcContext.getMethodSig
    val tarContext = srcContext.copy.removeTopContext()
    fact._2 match {
      case pdd: ParamDefDesc =>
        tarContext.setContext(procSig, pdd.locUri)
      case ldd: LocDefDesc => 
        tarContext.setContext(procSig, ldd.locUri)
      case dd: DefDesc =>
        if(dd.isDefinedInitially){
          tarContext.setContext(procSig, "Entry")
        } else if(dd.isUndefined) {
          tarContext.setContext(procSig, "Entry")
        } else throw new RuntimeException("Unexpected DefDesc: " + dd)
    }
  }
  
  private def isGlobal(slot: Slot): Boolean = 
    slot match{
      case vs: VarSlot => vs.varName.startsWith("@@")
      case _ => false
    }
  
  private def isDef(defDesc: DefDesc): Boolean =
    defDesc match{
      case _: LocDefDesc => true
      case _ => false
    }

  /**
   * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
   */
  class Gen extends MonotonicFunction[Node, IRDFact] {
    def apply(s: ISet[IRDFact], e: Statement, currentNode: Node): ISet[IRDFact] = {
      e match {
        case _: AssignmentStatement =>
          val succs = icfg.successors(currentNode)
          val globFacts =
            if(succs.isEmpty) isetEmpty[IRDFact]
            else succs.map(node => factSet(node).filter(fact => isGlobal(fact._1._1) && isDef(fact._1._2))).reduce(iunion[IRDFact])
          val globDefFacts = globFacts.filter(fact => isDef(fact._1._2))
          val flowingGlobFacts = s.filter(fact => isGlobal(fact._1._1) && isDef(fact._1._2))
          factSet += (currentNode -> (factSet.getOrElse(currentNode, isetEmpty) -- globFacts ++ flowingGlobFacts ++ globDefFacts))
          globDefFacts
        case _ =>
          isetEmpty
      }
    }
  }
  
  /**
   * @author Fengguo Wei & Sankardas Roy
   */
  class Kill extends MonotonicFunction[Node, IRDFact] {
    def apply(s: ISet[IRDFact], e: Statement, currentNode: Node): ISet[IRDFact] = {
      e match {
        case _: AssignmentStatement =>
          val node = currentNode
          val succs = icfg.successors(node)
          val globDefFacts =
            if(succs.isEmpty) isetEmpty[IRDFact]
            else succs.map(node => factSet(node).filter(fact => isGlobal(fact._1._1) && isDef(fact._1._2))).reduce(iunion[IRDFact])
          val redefGlobSlots = globDefFacts.filter(fact => s.map(_._1._1).contains(fact._1._1)).map(_._1._1)
          s.filter(f => !redefGlobSlots.contains(f._1._1))
        case _ => s
      }
    }
  }

  /**
    * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
    * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
    */
  class Callr extends CallResolver[Node, IRDFact] {
    /**
     * It returns the facts for each callee entry node and caller return node
     */
    def resolveCall(s: ISet[IRDFact], cj: CallStatement, callerNode: Node): (IMap[Node, ISet[IRDFact]], ISet[IRDFact]) = {
      var calleeFactsMap: IMap[ICFGNode, ISet[IRDFact]] = imapEmpty
      var returnFacts: ISet[IRDFact] = isetEmpty
      val callNode = icfg.getICFGCallNode(callerNode.getContext)
      icfg.successors(callNode).foreach {
        case suc@(_: ICFGEntryNode) =>
          calleeFactsMap += (suc -> s)
        case _: ICFGReturnNode =>
          returnFacts ++= s
        case _ =>
      }
      (calleeFactsMap, returnFacts)
    }
    
    def getAndMapFactsForCaller(calleeS: ISet[IRDFact], callerNode: Node, calleeExitNode: Node): ISet[IRDFact] = {
      calleeS
    }

    def needReturnNode(): Boolean = true
    
  }
  
}
