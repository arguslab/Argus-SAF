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

import java.io.Writer

import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.Property.Key
import org.argus.jawa.core.util._
import org.jgrapht._
import org.jgrapht.alg.shortestpath.DijkstraShortestPath
import org.jgrapht.ext._
import org.jgrapht.graph._

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirGraphImpl[N <: AlirNode] extends AlirGraph[N] {
  self =>

  private val factory = new EdgeFactory[N, Edge] {
    def createEdge(source : N, target : N) =
      new AlirEdge(self, source, target)
  }
  protected val graph = new DirectedPseudograph(factory)

  protected val pl: MMap[AlirNode, N] = cmapEmpty

  def pool: MMap[AlirNode, N] = pl

  protected val vIDProvider: ComponentNameProvider[N] = new ComponentNameProvider[N]() {
    def filterLabel(uri: String): String = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getName(v: N): String = {
      filterLabel(v.toString)
    }
  }

  protected val eIDProvider: ComponentNameProvider[Edge] = new ComponentNameProvider[Edge]() {
    def filterLabel(uri: String): String = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getName(e: Edge): String = {
      filterLabel(e.source.toString) + "-" + filterLabel(e.target.toString)
    }
  }

  def toDot(w: Writer, vlp: ComponentNameProvider[N] = vIDProvider): Unit = {
    val de = new DOTExporter[N, Edge](vlp, vlp, null)
    de.exportGraph(graph, w)
  }

  def toGraphML(w: Writer, vip: ComponentNameProvider[N] = vIDProvider, vlp: ComponentNameProvider[N] = vIDProvider, eip: ComponentNameProvider[Edge] = eIDProvider, elp: ComponentNameProvider[Edge] = null): Unit = {
    val graphml = new GraphMLExporter[N, Edge](vip, vlp, eip, elp)
    graphml.exportGraph(graph, w)
  }

  def toGML(w: Writer, vip: ComponentNameProvider[N] = vIDProvider, vlp: ComponentNameProvider[N] = vIDProvider, eip: ComponentNameProvider[Edge] = eIDProvider, elp: ComponentNameProvider[Edge] = null): Unit = {
    val gml = new GmlExporter[N, Edge](vip, vlp, eip, elp)
    gml.exportGraph(graph, w)
  }

  def findPath(srcNode: N, tarNode: N): IList[Edge] = {
    import scala.collection.JavaConverters._

    Option(DijkstraShortestPath.findPathBetween(this.graph, srcNode, tarNode)) match {
      case Some(path) => path.getEdgeList.asScala.toList
      case None => ilistEmpty
    }
  }

  def addNode(node : N) : N = {
    val n = pool.get(node) match {
      case Some(no) => no
      case None =>
        this.pl += node -> node
        node
    }
    graph.addVertex(n)
    n
  }

  def getNode(n : N) : N =
    pool(n)

  def deleteNode(node: N): Boolean =
    graph.removeVertex(node)

  def deleteEdge(source: N, target: N): Edge =
    graph.removeEdge(getNode(source), getNode(target))

  def deleteEdge(e: Edge): Boolean = graph.removeEdge(e)
}

trait AlirLoc {
  def locUri: String
  def locIndex: Int
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
abstract class AlirNode extends PropertyProvider with Serializable {
  val propertyMap: MLinkedMap[Key, Any] = mlinkedMapEmpty[Property.Key, Any]
  protected var owner: Signature = _
  def setOwner(owner: Signature): Unit = this.owner = owner
  def getOwner: Signature = this.owner
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
abstract class InterProceduralNode(context: Context) extends AlirNode {
  def getContext: Context = this.context
}