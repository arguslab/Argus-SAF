/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow

import org.argus.jawa.flow.util.DirectedGraphUtil
import org.argus.jawa.core.util.Property.Key
import org.argus.jawa.core.util._
import org.jgrapht._
import org.jgrapht.alg.KosarajuStrongConnectivityInspector

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirGraph[Node] {
  type Edge = AlirEdge[Node]

  protected def graph: DirectedGraph[Node, Edge]

  def nodes: Iterable[Node] = {
    import scala.collection.JavaConverters._

    graph.vertexSet.asScala
  }

  def numOfNodes: Int = graph.vertexSet.size

  def edges: Iterable[Edge] = {
    import scala.collection.JavaConverters._

    graph.edgeSet.asScala
  }

  def getEdges(n1: Node, n2: Node): CSet[Edge] = {
    import scala.collection.JavaConverters._

    graph.getAllEdges(n1, n2).asScala
  }

  def hasEdge(n1: Node, n2: Node): Boolean = graph.containsEdge(n1, n2)

  def numOfEdges: Int = graph.edgeSet.size

  def hasNode(n: Node): Boolean = graph.containsVertex(n)

  def getNode(n: Node): Node

  def prePostNodeOrder(n: Node): MMap[Node, (Int, Int)] =
    DirectedGraphUtil.computePrePostNodeOrder(graph, n)

  def stronglyConnectedSets: Iterable[CSet[Node]] = {
    import scala.collection.JavaConverters._

    val sci = new KosarajuStrongConnectivityInspector[Node, Edge](graph)
    sci.stronglyConnectedSets.asScala.map { s => s.asScala: CSet[Node] }
  }
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
final class AlirEdge[Node](val owner: AlirGraph[Node],
                           val source: Node, val target: Node)
    extends PropertyProvider {
  val propertyMap: MLinkedMap[Key, Any] = mlinkedMapEmpty[Property.Key, Any]
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirEdgeAccesses[Node] {
  self: AlirGraph[Node] =>

  def addNode(node: Node): Node

  def addEdge(source: Node, target: Node): Edge =
    graph.addEdge(getNode(source), getNode(target))

  def addEdge(e: Edge): Boolean = graph.addEdge(e.source, e.target, e)
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirSuccPredAccesses[Node] {
  self: AlirGraph[Node] =>

  def successors(node: Node): CSet[Node] = {

    successorEdges(node).map(edgeTarget)
  }

  def successorEdges(node: Node): CSet[Edge] = {
    import scala.collection.JavaConverters._

    if (graph.containsVertex(node))
      graph.outgoingEdgesOf(node).asScala
    else
      Set()
  }

  def successor(edge: Edge): Node = edgeTarget(edge)

  def predecessor(edge: Edge): Node = edgeSource(edge)

  def predecessors(node: Node): CSet[Node] = {

    predecessorEdges(node).map(edgeSource)
  }

  def predecessorEdges(node: Node): CSet[Edge] = {
    import scala.collection.JavaConverters._

    if (graph.containsVertex(node))
      graph.incomingEdgesOf(node).asScala
    else
      Set()
  }

  protected def edgeSource(edge: AlirEdge[Node]): Node = edge.source
  protected def edgeTarget(edge: AlirEdge[Node]): Node = edge.target
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirDependentAccesses[Node] {
  self: AlirGraph[Node] =>

  def dependents(node: Node): CSet[Node] = {

    dependentEdges(node).map(edgeTarget)
  }

  def dependentEdges(node: Node): CSet[Edge] = {
    import scala.collection.JavaConverters._

    if (graph.containsVertex(node))
      graph.outgoingEdgesOf(node).asScala
    else
      Set()
  }

  def dependent(edge: Edge): Node = {
    edgeTarget(edge)
  }

  def dependee(edge: Edge): Node = {
    edgeSource(edge)
  }

  def dependee(node: Node): CSet[Node] = {

    dependeeEdges(node).map(edgeSource)
  }

  def dependeeEdges(node: Node): CSet[Edge] = {
    import scala.collection.JavaConverters._

    if (graph.containsVertex(node))
      graph.incomingEdgesOf(node).asScala
    else
      Set()
  }

  protected def edgeSource(edge: AlirEdge[Node]): Node = edge.source
  protected def edgeTarget(edge: AlirEdge[Node]): Node = edge.target
}
