/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.controlFlowGraph

import org.sireum.alir._
import org.sireum.pilar.ast._
import org.sireum.pilar.symbol._
import org.sireum.util._
import org.sireum.alir.{ControlFlowGraph => OrigControlFlowGraph}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 * Modified by Fengguo Wei
 */
object ControlFlowGraph {
  val BRANCH_PROPERTY_KEY = OrigControlFlowGraph.BRANCH_PROPERTY_KEY
  type Node = OrigControlFlowGraph.Node
  type Edge = OrigControlFlowGraph.Edge
  type ShouldIncludeFlowFunction = OrigControlFlowGraph.ShouldIncludeFlowFunction
  val defaultSiff: ShouldIncludeFlowFunction = { (_, _) => (Array.empty[CatchClause], false) }

  def apply[VirtualLabel] = build[VirtualLabel] _

  def build[VirtualLabel] //
  (pst: ProcedureSymbolTable,
   entryLabel: VirtualLabel, exitLabel: VirtualLabel,
   pool: AlirIntraProceduralGraph.NodePool,
   shouldIncludeFlow: ShouldIncludeFlowFunction = defaultSiff): ControlFlowGraph[VirtualLabel] = {

    val locationDecls = pst.locations
    val result = new Cfg[VirtualLabel](pool)
    if (locationDecls.isEmpty) return result

      def getLocUriIndex(l: LocationDecl) =
        if (l.name.isEmpty)
          (None, l.index)
        else
          (Some(l.name.get.uri), l.index)

      def getNode(l: LocationDecl) =
        if (l.name.isEmpty)
          result.getNode(None, l.index)
        else
          result.getNode(Some(l.name.get.uri), l.index)

    val verticesMap = mmapEmpty[ResourceUri, Node]
    for (ld <- locationDecls) {
      val lui = getLocUriIndex(ld)
      val n = result.addNode(lui._1, lui._2)
      if (ld.name.isDefined)
        verticesMap(lui._1.get) = n
    }

    val exitNode = result.addVirtualNode(exitLabel)
    result.entryNode = result.addVirtualNode(entryLabel)
    result.addEdge(result.entryNode, getNode(locationDecls.head))
    result.exitNode = exitNode
    var source: Node = null
    var next: Node = null
      def addGotoEdge(gj: GotoJump) = {
        val target = verticesMap(gj.target.uri)
        result.addEdge(source, target)
      }
    var transIndex = -1
    val visitor = Visitor.build({
      case al: ActionLocation =>
        al.action match {
          case ta: ThrowAction =>
          case _                => result.addEdge(source, next)
        }
        false
      case el: EmptyLocation =>
        if(next != null)
          result.addEdge(source, next)
        false
      case jl: JumpLocation =>
        transIndex = 0
        true
      case t: Transformation =>
        transIndex += 1
        if (t.actions.exists(_.isInstanceOf[ThrowAction])) {
          result.addEdge(source, exitNode)
          false
        } else if (t.jump.isEmpty) {
          result.addEdge(source, next)
          false
        } else {
          true
        }
      case t: CallJump if t.jump.isEmpty =>
        result.addEdge(source, next)
        false
      case gj: GotoJump =>
        addGotoEdge(gj)
        false
      case rj: ReturnJump =>
        result.addEdge(source, exitNode)
        false
      case ifj: IfJump =>
        var i = 1
        for (iftj <- ifj.ifThens) {
          val target = verticesMap(iftj.target.uri)
          val e = result.addEdge(source, target)
          putBranchOnEdge(transIndex, i, e)
          i += 1
        }
        if (ifj.ifElse.isEmpty)
          result.addEdge(source, next)
        else {
          val gj = ifj.ifElse.get
          putBranchOnEdge(transIndex, 0, addGotoEdge(gj))
        }
        false
      case sj: SwitchJump =>
        var i = 1
        for (scj <- sj.cases) {
          val target = verticesMap(scj.target.uri)
          val e = result.addEdge(source, target)
          putBranchOnEdge(transIndex, i, e)
          i += 1
        }
        if (sj.defaultCase.isEmpty)
          result.addEdge(source, next)
        else {
          val gj = sj.defaultCase.get
          putBranchOnEdge(transIndex, 0, addGotoEdge(gj))
        }
        false
    })
    val size = locationDecls.size
    for (i <- 0 until size) {
      val l = locationDecls(i)
      source = getNode(l)
      next = if (i != size - 1) getNode(locationDecls(i + 1)) else null
      visitor(l)
      transIndex = -1
      if (shouldIncludeFlow ne defaultSiff) {
        val (ccs, toExit) = shouldIncludeFlow(l, pst.catchClauses(l.index))
        ccs.foreach { cc =>
          result.addEdge(source, verticesMap(cc.jump.target.uri))
        }
        if (toExit) result.addEdge(source, exitNode)
      }
    }

//    print(result)
    //result.useBranch(pst) {}

    result
  }

  private def putBranchOnEdge(trans: Int, branch: Int, e: Edge) = {
    e(BRANCH_PROPERTY_KEY) = (trans, branch)
  }

  private def getBranch(pst: ProcedureSymbolTable, e: Edge): Option[Branch] = {
    if (e ? BRANCH_PROPERTY_KEY) {
      val p: (Int, Int) = e(BRANCH_PROPERTY_KEY)
      var j =
        PilarAstUtil.getJumps(pst.location(
          e.source.asInstanceOf[AlirLocationNode].locIndex))(first2(p)).get
      val i = second2(p)

      j match {
        case jump: CallJump => j = jump.jump.get
        case _ =>
      }

      (j: @unchecked) match {
        case gj: GotoJump   => Some(gj)
        case rj: ReturnJump => Some(rj)
        case ifj: IfJump =>
          if (i == 0) ifj.ifElse
          else Some(ifj.ifThens(i - 1))
        case sj: SwitchJump =>
          if (i == 0) sj.defaultCase
          else Some(sj.cases(i - 1))
      }
    } else None
  }

  private class Cfg[VirtualLabel] //
  (val pool: AlirIntraProceduralGraph.NodePool)
      extends ControlFlowGraph[VirtualLabel]
      with AlirEdgeAccesses[Node] {

    private var succBranchMap: MMap[(Node, Option[Branch]), Node] = null
    private var predBranchMap: MMap[(Node, Option[Branch]), Node] = null

    var entryNode: Node = null

    var exitNode: Node = null

    def reverse: Cfg[VirtualLabel] = {
      val result = new Cfg[VirtualLabel](pool)
      for (n <- nodes) result.addNode(n)
      for (e <- edges) result.addEdge(e.target, e.source)
      result.entryNode = exitNode
      result.exitNode = entryNode
      result
    }

    def useBranch[T](pst: ProcedureSymbolTable)(f: => T): T = {
      succBranchMap = mmapEmpty
      predBranchMap = mmapEmpty
      for (node <- this.nodes) {
        for (succEdge <- successorEdges(node)) {
          val b = getBranch(pst, succEdge)
          val s = edgeSource(succEdge)
          val t = edgeTarget(succEdge)
          succBranchMap((node, b)) = t
          predBranchMap((t, b)) = s
        }
      }
      val result = f
      succBranchMap = null
      predBranchMap = null
      result
    }

    def successor(node: Node, branch: Option[Branch]): Node = {
      assert(succBranchMap != null,
        "The successor method needs useBranch as enclosing context")
      succBranchMap((node, branch))
    }

    def predecessor(node: Node, branch: Option[Branch]): Node = {
      assert(predBranchMap != null,
        "The successor method needs useBranch as enclosing context")
      predBranchMap((node, branch))
    }

    override def toString = {
      val sb = new StringBuilder("CFG\n")

      for (n <- nodes)
        for (m <- successors(n)) {
          for (e <- getEdges(n, m)) {
            val branch = if (e ? ControlFlowGraph.BRANCH_PROPERTY_KEY)
              e(ControlFlowGraph.BRANCH_PROPERTY_KEY).toString
            else ""
            sb.append("%s -> %s %s\n".format(n, m, branch))
          }
        }

      sb.append("\n")

      sb.toString
    }
  }
}
