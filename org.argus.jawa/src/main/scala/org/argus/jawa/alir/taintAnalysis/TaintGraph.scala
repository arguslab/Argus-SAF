/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.taintAnalysis

import org.argus.jawa.alir.{AlirEdgeAccesses, AlirGraphImpl, AlirSuccPredAccesses, InterProceduralNode}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class TaintGraph
    extends AlirGraphImpl[TaintNode]
    with AlirSuccPredAccesses[TaintNode]
    with AlirEdgeAccesses[TaintNode] {

  private val sources: MSet[TaintNode] = msetEmpty

  def addSource(src: TaintNode): Unit = {
    addNode(src)
    sources += src
  }
  
  def taintNodeExists(tf: TaintSlot): Boolean = {
    graph.containsVertex(newTaintNode(tf))
  }
  
  def getTaintNode(tf: TaintSlot): TaintNode =
    pool(newTaintNode(tf))
  
  protected def newTaintNode(tf: TaintSlot) =
    TaintNode(tf)
    
  def addTaintNode(tf: TaintSlot): TaintNode = {
    val node = newTaintNode(tf)
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def addTaintEdge(srcSlot: TaintSlot, tarSlot: TaintSlot): Unit = {
    if(!taintNodeExists(srcSlot)) addTaintNode(srcSlot)
    if(!taintNodeExists(tarSlot)) addTaintNode(tarSlot)
    addEdge(getTaintNode(srcSlot), getTaintNode(tarSlot))
  }
  
  def getSources: ISet[TaintNode] = this.sources.toSet
}

case class TaintNode(tf: TaintSlot) extends InterProceduralNode(tf.context){
  
}
