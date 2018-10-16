/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dda

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGEntryNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class MultiDataDependenceGraph[Node <: IDDGNode] extends DataDependenceBaseGraph[Node] {
  val icfg: InterProceduralControlFlowGraph[ICFGNode] = new InterProceduralControlFlowGraph[ICFGNode]
  val encontext: Context = new Context("MultiDataDependenceGraph").setContext(new Signature("LMDDGEntry;.entry:()V"), "L0000")
  icfg.addEntryNode(icfg.addICFGEntryNode(encontext).asInstanceOf[ICFGEntryNode])
  val entryNode: Node = addIDDGEntryNode(icfg.entryNode.asInstanceOf[ICFGEntryNode])
  
  private val loadedSet: MSet[IDDGEntryNode] = msetEmpty
  
  def isLoaded(iddg: DataDependenceBaseGraph[Node]): Boolean = {
    loadedSet.contains(iddg.entryNode.asInstanceOf[IDDGEntryNode])
  }
  
  def addGraph(iddg: DataDependenceBaseGraph[Node]): Unit = {
    if(isLoaded(iddg)) return
    this.synchronized{
      loadedSet += iddg.entryNode.asInstanceOf[IDDGEntryNode]
      icfg.merge(iddg.icfg)
      iddg.nodes.foreach(addNode)
      iddg.edges.foreach(addEdge)
    }
  }
}
