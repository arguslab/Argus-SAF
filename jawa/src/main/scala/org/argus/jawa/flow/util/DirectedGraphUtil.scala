/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.util

import org.argus.jawa.core.util._

/**
  * Created by fgwei on 4/14/17.
  */
object DirectedGraphUtil {
  def computePrePostNodeOrder[V, E](dg : org.jgrapht.DirectedGraph[V, E], v : V): MMap[V, (Int, Int)] = {
    val numOfNodes = dg.vertexSet.size
    val result = idmapEmpty[V, (Int, Int)](numOfNodes)
    val seen = idmapEmpty[V, V](numOfNodes)
    var preNum = 0
    var postNum = 0
    def dfs(v : V) : Unit = {
      if (seen.contains(v)) return
      seen.put(v, v)
      val pre = preNum
      preNum += 1
      val it = dg.outgoingEdgesOf(v).iterator
      while (it.hasNext) {
        dfs(dg.getEdgeTarget(it.next))
      }
      val post = postNum
      postNum += 1
      result(v) = (pre, post)
    }
    dfs(v)
    result
  }

  def postOrderedNodes[V](m : MMap[V, (Int, Int)]): MArray[V] = {
    val a = marrayEmpty[(V, Int)]
    m.foreach { e =>
      a += ((e._1, e._2._2))
    }
    a.sortBy(_._2).map(_._1)
  }
}