/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dfa

import org.argus.jawa.flow.{AlirLoc, Context}
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.interprocedural.CallResolver
import org.argus.jawa.core.ast.{Location, MethodDeclaration, ResolvedBody, Statement}
import org.argus.jawa.core.Global
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

/**
  * Created by fgwei on 4/16/17.
  */
class IntraIngredientProvider[LatticeElement](md: MethodDeclaration, cfg: IntraProceduralControlFlowGraph[CFGNode]) extends IngredientProvider[CFGNode, LatticeElement, (String, Int)] {
  override def getBody(sig: Signature): ResolvedBody = md.resolvedBody
  override def newLoc(currentNode: CFGNode with AlirLoc, newl: Location): (String, Int) = {
    (newl.locationUri, newl.locationIndex)
  }

  override def next(currentNode: CFGNode with AlirLoc, body: ResolvedBody): CFGNode = {
    val nl = body.locations(currentNode.locIndex + 1)
    cfg.getNode(nl)
  }

  override def node(l: Location, loc: (String, Int)): CFGNode = cfg.getNode(loc._1, loc._2)

  override def exitNode(currentNode: CFGNode): CFGNode = cfg.exitNode

  override def returnNode(currentNode: CFGNode with AlirLoc): CFGNode = throw new RuntimeException("Should not be called.")

  def process(
      startNode: CFGNode,
      mdaf: MonotoneDataFlowAnalysisBuilder[CFGNode, LatticeElement],
      callr: Option[CallResolver[CFGNode, LatticeElement]]): Unit = {
    val workList = mlistEmpty[CFGNode]

    workList += startNode
    while (workList.nonEmpty) {
      val n = workList.remove(0)
      n match {
        case ln: CFGLocationNode =>
          if (mdaf.visit(ln)) {
            workList ++= cfg.successors(n)
          }
        case _ =>
          for (succ <- cfg.successors(n)) {
            mdaf.update(mdaf.entrySet(n), succ)
            workList += succ
          }
      }
    }
  }

  def preProcess(node: CFGNode, statement: Statement, s: ISet[LatticeElement]): Unit = {}
  def postProcess(node: CFGNode, statement: Statement, s:ISet[LatticeElement]): Unit = {}

  override def onPreVisitNode(node: CFGNode, preds: CSet[CFGNode]): Unit = {}

  override def onPostVisitNode(node: CFGNode, succs: CSet[CFGNode]): Unit = {}
}

class InterIngredientProvider[LatticeElement](global: Global, icfg: InterProceduralControlFlowGraph[ICFGNode]) extends IngredientProvider[ICFGNode, LatticeElement, Context] {

  def getBody(sig: Signature): ResolvedBody = {
    global.getMethod(sig).get.getBody.resolvedBody
  }

  override def newLoc(currentNode: ICFGNode with AlirLoc, newl: Location): Context =
    currentNode.getContext.copy.removeTopContext().setContext(currentNode.getOwner, newl.locationUri)

  override def next(currentNode: ICFGNode with AlirLoc, body: ResolvedBody): ICFGNode = {
    val newLoc = body.locations(currentNode.locIndex + 1)
    val newContext = currentNode.getContext.copy.removeTopContext()
    newContext.setContext(currentNode.getOwner, newLoc.locationUri)
    if(icfg.isCall(newLoc))
      icfg.getICFGCallNode(newContext)
    else
      icfg.getICFGNormalNode(newContext)
  }

  override def node(l: Location, loc: Context): ICFGNode = {
    if(icfg.isCall(l))
      icfg.getICFGCallNode(loc)
    else
      icfg.getICFGNormalNode(loc)
  }

  override def exitNode(currentNode: ICFGNode): ICFGNode = {
    val exitContext = currentNode.getContext.copy.removeTopContext().setContext(currentNode.getOwner, "Exit")
    icfg.getICFGExitNode(exitContext)
  }

  override def returnNode(currentNode: ICFGNode with AlirLoc): ICFGNode = {
    icfg.getICFGReturnNode(currentNode.getContext)
  }

  def process(
      startNode: ICFGNode,
      mdaf: MonotoneDataFlowAnalysisBuilder[ICFGNode, LatticeElement],
      callr: Option[CallResolver[ICFGNode, LatticeElement]]): Unit = {
    def doProcess(n: ICFGNode): ISet[ICFGNode] = {
      var result = isetEmpty[ICFGNode]
      n match {
        case en: ICFGEntryNode =>
          for (succ <- icfg.successors(en)) {
            if (mdaf.update(mdaf.entrySet(en), succ)) {
              result += succ
            }
          }
        case xn: ICFGExitNode =>
          if (callr.isDefined) {
            for (succ <- icfg.successors(n)) {
              val factsForCaller = callr.get.getAndMapFactsForCaller(mdaf.entrySet(xn), succ, xn)
              mdaf.update(mdaf.confluence(mdaf.entrySet(succ), factsForCaller), succ)
              result += succ
            }
          }
        case cn: ICFGCallNode =>
          if (mdaf.visit(cn)) {
            result ++= icfg.successors(n)
          }
        case _: ICFGReturnNode =>
          for (succ <- icfg.successors(n)) {
            if (mdaf.update(mdaf.entrySet(n), succ)) {
              result += succ
            }
          }
        case nn: ICFGNormalNode =>
          if (mdaf.visit(nn)) {
            result ++= icfg.successors(n)
          }
        case a => throw new RuntimeException("unexpected node type: " + a)
      }
      result
    }
    val workList = mlistEmpty[ICFGNode]
    workList += startNode
    val ensurer = new ConvergeEnsurer[ICFGNode]
    var i = 0
    while(workList.nonEmpty){
      while (workList.nonEmpty) {
        val n = workList.remove(0)
        i += 1
        if(ensurer.checkNode(n)) {
          ensurer.updateNodeCount(n)
          onPreVisitNode(n, icfg.predecessors(n))
          val newWorks = doProcess(n)
          workList ++= {newWorks -- workList}
          onPostVisitNode(n, icfg.successors(n))
        }
      }
      val nodes = icfg.nodes
      workList ++= nodes.map{ node =>
        var newnodes = isetEmpty[ICFGNode]
        node match {
          case xn: ICFGExitNode =>
            if(ensurer.checkNode(xn)) {
              onPreVisitNode(xn, icfg.predecessors(xn))
              val succs = icfg.successors(xn)
              for (succ <- succs) {
                val factsForCaller = callr.get.getAndMapFactsForCaller(mdaf.entrySet(xn), succ, xn)
                if (mdaf.update(mdaf.confluence(mdaf.entrySet(succ), factsForCaller), succ))
                  newnodes += succ
              }
              onPostVisitNode(xn, succs)
            }
          case _ =>
        }
        newnodes
      }.reduce(iunion[ICFGNode])
    }
  }

  def preProcess(node: ICFGNode, statement: Statement, s: ISet[LatticeElement]): Unit = {}
  def postProcess(node: ICFGNode, statement: Statement, s: ISet[LatticeElement]): Unit = {}
  override def onPreVisitNode(node: ICFGNode, preds: CSet[ICFGNode]): Unit = {}
  override def onPostVisitNode(node: ICFGNode, succs: CSet[ICFGNode]): Unit = {}
}

/**
  * Theoretically the algorithm should converge if it's implemented correctly, but just in case.
  */
class ConvergeEnsurer[N] {
  private val limit: Int = 10
  private val usageMap: MMap[N, Int] = mmapEmpty
  private val nonConvergeNodes: MSet[N] = msetEmpty
  def checkNode(n: N): Boolean = {
    val c = this.usageMap.getOrElseUpdate(n, 0)
    if(c >= limit){
      this.nonConvergeNodes += n
      false
    }
    else true
  }
  def updateNodeCount(n: N): Unit = this.usageMap(n) = this.usageMap.getOrElseUpdate(n, 0) + 1
}