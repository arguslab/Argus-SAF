/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.dataDependenceAnalysis

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGEntryNode, ICFGNode, InterproceduralControlFlowGraph}
import org.argus.jawa.core.Signature
import org.sireum.util._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class MultiDataDependenceGraph[Node <: IDDGNode] extends DataDependenceBaseGraph[Node] {
  val icfg: InterproceduralControlFlowGraph[ICFGNode] = new InterproceduralControlFlowGraph[ICFGNode]
  val encontext = new Context().setContext(new Signature("LMDDGEntry;.entry:()V"), "L0000")
  icfg.addEntryNode(icfg.addICFGEntryNode(encontext).asInstanceOf[ICFGEntryNode])
  val entryNode: Node = addIDDGEntryNode(icfg.entryNode.asInstanceOf[ICFGEntryNode])
  
  private val loadedSet: MSet[IDDGEntryNode] =msetEmpty
  
  def isLoaded(iddg: DataDependenceBaseGraph[Node]): Boolean = {
    loadedSet.contains(iddg.entryNode.asInstanceOf[IDDGEntryNode])
  }
  
  def addGraph(iddg: DataDependenceBaseGraph[Node]): Unit = {
    if(isLoaded(iddg)) return
    this.synchronized{
      loadedSet += iddg.entryNode.asInstanceOf[IDDGEntryNode]
      icfg.merge(iddg.icfg)
      this.pl ++= iddg.pool
      iddg.nodes.foreach(addNode(_))
      iddg.edges.foreach(addEdge(_))
    }
  }
}
