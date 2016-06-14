/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.interprocedural

import java.io.Writer

import org.argus.jawa.alir.Context
import org.jgrapht.EdgeFactory
import org.jgrapht.alg.DijkstraShortestPath
import org.jgrapht.ext._
import org.jgrapht.graph.DirectedPseudograph
import org.sireum.alir._
import org.sireum.util._

import scala.collection.mutable

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait InterproceduralGraph[Node <: InterproceduralNode]
  extends AlirGraph[Node]
  with AlirEdgeAccesses[Node]
  with AlirSuccPredAccesses[Node]
  with Serializable {

  self=>

  protected val graph = new DirectedPseudograph(
    new EdgeFactory[Node, Edge] {
      def createEdge(source: Node, target: Node) =
        new AlirEdge(self, source, target)
    })

  def addNode(node: Node): Node = {
    require(pool(node) eq node)
    graph.addVertex(node)
    node
  }

  def getNode(n: Node): Node =
    pool(n)

  def deleteNode(node: Node): Boolean =
    graph.removeVertex(node)

  def deleteEdge(source: Node, target: Node): Edge =
    graph.removeEdge(getNode(source), getNode(target))

  def deleteEdge(e: Edge) = graph.removeEdge(e)

  protected val pl: MMap[InterproceduralNode, Node] = new mutable.HashMap[InterproceduralNode, Node] with mutable.SynchronizedMap[InterproceduralNode, Node]

  def pool: MMap[InterproceduralNode, Node] = pl

  protected val vIDProvider = new VertexNameProvider[Node]() {
    def filterLabel(uri: String) = {
		  uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
		}

		def getVertexName(v: Node): String = {
		  filterLabel(v.toString)
		}
  }

  protected val vLDProvider = new VertexNameProvider[Node]() {
    def filterLabel(uri: String) = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getVertexName(v: Node): String = {
      filterLabel(v.toString)
    }
  }

  protected val eIDProvider = new EdgeNameProvider[Edge]() {
    def filterLabel(uri: String) = {
      uri.filter(_.isUnicodeIdentifierPart)  // filters out the special characters like '/', '.', '%', etc.
    }

    def getEdgeName(e: Edge): String = {
      filterLabel(e.source.toString) + "-" + filterLabel(e.target.toString)
    }
  }

  def toDot(w: Writer, vlp: VertexNameProvider[Node] = vIDProvider) = {
    val de = new DOTExporter[Node, Edge](vlp, vlp, null)
    de.export(w, graph)
  }

  def toGraphML(w: Writer, vip: VertexNameProvider[Node] = vIDProvider, vlp: VertexNameProvider[Node] = vLDProvider, eip: EdgeNameProvider[Edge] = eIDProvider, elp: EdgeNameProvider[Edge] = null) = {
    val graphml = new GraphMLExporter[Node, Edge](vip, vlp, eip, elp)
    graphml.export(w, graph)
  }

  def toGML(w: Writer, vip: VertexNameProvider[Node] = vIDProvider, vlp: VertexNameProvider[Node] = vLDProvider, eip: EdgeNameProvider[Edge] = eIDProvider, elp: EdgeNameProvider[Edge] = null) = {
    val gml = new GmlExporter[Node, Edge](vip, vlp, eip, elp)
    gml.export(w, graph)
  }

  def findPath(srcNode: Node, tarNode: Node): IList[Edge] = {
    import scala.collection.JavaConversions._
	  val path = DijkstraShortestPath.findPathBetween(this.graph, srcNode, tarNode)
	  if(path != null) path.toList
	  else ilistEmpty
	}
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
abstract class InterproceduralNode(context: Context) extends PropertyProvider with Serializable {
  val propertyMap = mlinkedMapEmpty[Property.Key, Any]
  def getContext = this.context
}
