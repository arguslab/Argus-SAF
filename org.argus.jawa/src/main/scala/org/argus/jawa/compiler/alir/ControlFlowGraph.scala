/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.alir

import org.sireum.alir._
import org.argus.jawa.compiler.parser.{Location => JawaLocation, _}
import org.sireum.util._

trait ControlFlowGraph[VirtualLabel]
    extends AlirIntraProceduralGraph[ControlFlowGraph.Node, VirtualLabel]
    with AlirSuccPredAccesses[ControlFlowGraph.Node] {

  def entryNode : ControlFlowGraph.Node
  def exitNode : ControlFlowGraph.Node
  def reverse : ControlFlowGraph[VirtualLabel]
}

object ControlFlowGraph {
  val BRANCH_PROPERTY_KEY = "BRANCH"
  type Node = AlirIntraProceduralNode
  type Edge = AlirEdge[Node]
  type ShouldIncludeFlowFunction = (JawaLocation, Iterable[CatchClause]) => (Iterable[CatchClause], Boolean)

  val defaultSiff : ShouldIncludeFlowFunction =
    { (_, catchclauses) =>
        val result = catchclauses        
        (result, false)
    }
  
  def apply[VirtualLabel](
    md : MethodDeclaration,
    entryLabel : VirtualLabel, exitLabel : VirtualLabel,
    pool : AlirIntraProceduralGraph.NodePool,
    shouldIncludeFlow : ShouldIncludeFlowFunction = defaultSiff): ControlFlowGraph[VirtualLabel] = build[VirtualLabel](md, entryLabel, exitLabel, pool, shouldIncludeFlow)

  def build[VirtualLabel](
    md : MethodDeclaration,
    entryLabel : VirtualLabel, exitLabel : VirtualLabel,
    pool : AlirIntraProceduralGraph.NodePool,
    shouldIncludeFlow : ShouldIncludeFlowFunction = defaultSiff): ControlFlowGraph[VirtualLabel] = {

    val body = md.body match {
      case rb: ResolvedBody => rb
      case ub: UnresolvedBody => ub.resolve
    }
    val locationDecls = body.locations
    val result = new Cfg[VirtualLabel](pool)
    if (locationDecls.isEmpty) return result

      def getLocUriIndex(l : JawaLocation) =
        (l.locationUri, l.locationIndex)

      def getNode(l : JawaLocation) =
        result.getNode(Some(l.locationUri), l.locationIndex)

    val verticesMap = mmapEmpty[ResourceUri, Node]
    for (ld <- locationDecls) {
      val lui = getLocUriIndex(ld)
      val n = result.addNode(Some(lui._1), lui._2)
      verticesMap(lui._1) = n
    }

    val exitNode = result.addVirtualNode(exitLabel)
    result.entryNode = result.addVirtualNode(entryLabel)
    result.addEdge(result.entryNode, getNode(locationDecls.head))
    result.exitNode = exitNode
    var source : Node = null
    var next : Node = null
    
    val size = locationDecls.size
    for (i <- 0 until size) {
      val l = locationDecls(i)
      source = getNode(l)
      next = if (i != size - 1) getNode(locationDecls(i + 1)) else exitNode
      l.statement match {
        case _: CallStatement =>
          result.addEdge(source, next)
        case _: AssignmentStatement =>
          result.addEdge(source, next)
        case _: ThrowStatement =>
          result.addEdge(source, exitNode)
        case is: IfStatement =>
          result.addEdge(source, next)
          next = verticesMap.getOrElse(is.targetLocation.location, exitNode)
          result.addEdge(source, next)
        case gs: GotoStatement =>
          next = verticesMap.getOrElse(gs.targetLocation.location, exitNode)
          result.addEdge(source, next)
        case ss: SwitchStatement =>
          ss.cases foreach {
            c =>
              next = verticesMap.getOrElse(c.targetLocation.location, exitNode)
              result.addEdge(source, next)
          }
          ss.defaultCaseOpt match {
            case Some(d) =>
              next = verticesMap.getOrElse(d.targetLocation.location, exitNode)
              result.addEdge(source, next)
            case None => result.addEdge(source, next)
          }
        case _: ReturnStatement =>
          result.addEdge(source, exitNode)
        case _: MonitorStatement =>
          result.addEdge(source, next)
        case _: EmptyStatement =>
          result.addEdge(source, next)
        case _ =>
          result.addEdge(source, next)
      }
      val (ccs, toExit) = shouldIncludeFlow(l, body.getCatchClauses(l.locationSymbol.locationIndex))
      ccs.foreach { cc =>
        result.addEdge(source, verticesMap.getOrElse(cc.targetLocation.location, exitNode))
      }
      if (toExit) result.addEdge(source, exitNode)
    }
    result
  }

  private class Cfg[VirtualLabel] //
  (val pool : AlirIntraProceduralGraph.NodePool)
      extends ControlFlowGraph[VirtualLabel]
      with AlirEdgeAccesses[Node] {

    var entryNode : Node = _

    var exitNode : Node = _

    def reverse : Cfg[VirtualLabel] = {
      val result = new Cfg[VirtualLabel](pool)
      for (n <- nodes) result.addNode(n)
      for (e <- edges) result.addEdge(e.target, e.source)
      result.entryNode = exitNode
      result.exitNode = entryNode
      result
    }

    override def toString: String = {
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
