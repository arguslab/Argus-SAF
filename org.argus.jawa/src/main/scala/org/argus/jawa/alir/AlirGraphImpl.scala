/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir

import java.io.Writer

import org.argus.jawa.core.Signature
import org.argus.jawa.core.util.Property.Key
import org.argus.jawa.core.util._
import org.jgrapht._
import org.jgrapht.alg.DijkstraShortestPath
import org.jgrapht.ext._
import org.jgrapht.graph._

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
trait AlirGraphImpl[N <: AlirNode] extends AlirGraph[N] {
  self =>

  protected val graph = new DirectedPseudograph(
    new EdgeFactory[N, Edge] {
      def createEdge(source : N, target : N) =
        new AlirEdge(self, source, target)
    })

  val pl: MMap[AlirNode, N] = cmapEmpty

  def pool: MMap[AlirNode, N] = pl

  protected val vIDProvider = new VertexNameProvider[N]() {
    def filterLabel(uri: String): String = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getVertexName(v: N): String = {
      filterLabel(v.toString)
    }
  }

  protected val eIDProvider = new EdgeNameProvider[Edge]() {
    def filterLabel(uri: String): String = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getEdgeName(e: Edge): String = {
      filterLabel(e.source.toString) + "-" + filterLabel(e.target.toString)
    }
  }

  def toDot(w: Writer, vlp: VertexNameProvider[N] = vIDProvider): Unit = {
    val de = new DOTExporter[N, Edge](vlp, vlp, null)
    de.export(w, graph)
  }

  def toGraphML(w: Writer, vip: VertexNameProvider[N] = vIDProvider, vlp: VertexNameProvider[N] = vIDProvider, eip: EdgeNameProvider[Edge] = eIDProvider, elp: EdgeNameProvider[Edge] = null): Unit = {
    val graphml = new GraphMLExporter[N, Edge](vip, vlp, eip, elp)
    graphml.export(w, graph)
  }

  def toGML(w: Writer, vip: VertexNameProvider[N] = vIDProvider, vlp: VertexNameProvider[N] = vIDProvider, eip: EdgeNameProvider[Edge] = eIDProvider, elp: EdgeNameProvider[Edge] = null): Unit = {
    val gml = new GmlExporter[N, Edge](vip, vlp, eip, elp)
    gml.export(w, graph)
  }

  def findPath(srcNode: N, tarNode: N): IList[Edge] = {
    import scala.collection.JavaConverters._
    val path = DijkstraShortestPath.findPathBetween(this.graph, srcNode, tarNode)
    if(path != null) path.asScala.toList
    else ilistEmpty
  }

  def addNode(node : N) : N = {
    require(pool(node) eq node)
    graph.addVertex(node)
    node
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