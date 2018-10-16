/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import org.jgrapht.graph.DirectedPseudograph
import org.jgrapht.traverse.TopologicalOrderIterator
import org.jgrapht.{DirectedGraph, EdgeFactory}

/**
  * Created by fgwei on 5/18/17.
  */
object TopologicalSortUtil {
  def sort[Node](map: IMap[Node, ISet[Node]]): IList[Node] = {
    final class TempEdge(val source: Node, val target: Node)
    val factory = new EdgeFactory[Node, TempEdge] {
      def createEdge(source: Node, target: Node) = new TempEdge(source, target)
    }
    val graph: DirectedGraph[Node, TempEdge] = new DirectedPseudograph[Node, TempEdge](factory)
    map.foreach {
      case (caller, callees) =>
        graph.addVertex(caller)
        callees.foreach { callee =>
          if(!graph.containsVertex(callee)) {
            graph.addVertex(callee)
          }
          graph.addEdge(caller, callee)
        }
    }
    val ite = new TopologicalOrderIterator(graph)
    val list: MList[Node] = mlistEmpty
    while(ite.hasNext) {
      list += ite.next()
    }
    list.toList
  }
}
