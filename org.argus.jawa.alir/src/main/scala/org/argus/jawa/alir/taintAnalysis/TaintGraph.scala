/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.taintAnalysis

import org.argus.jawa.alir.interprocedural.{InterproceduralGraph, InterproceduralNode}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class TaintGraph extends InterproceduralGraph[TaintNode]{
  private val sources: MSet[TaintNode] = msetEmpty
  def addSource(src: TaintNode) = {
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
  
  def addTaintEdge(srcSlot: TaintSlot, tarSlot: TaintSlot) = {
    if(!taintNodeExists(srcSlot)) addTaintNode(srcSlot)
    if(!taintNodeExists(tarSlot)) addTaintNode(tarSlot)
    addEdge(getTaintNode(srcSlot), getTaintNode(tarSlot))
  }
  
  def getSources = this.sources.toSet
}

case class TaintNode(tf: TaintSlot) extends InterproceduralNode(tf.context){
  
}
