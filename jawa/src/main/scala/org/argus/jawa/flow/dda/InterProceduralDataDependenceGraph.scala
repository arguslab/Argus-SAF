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

import org.argus.jawa.flow.cfg._
import org.argus.jawa.core.Global

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class InterProceduralDataDependenceGraph[Node <: IDDGNode] extends DataDependenceBaseGraph[Node]{

  protected var entryN: IDDGEntryNode = _
  def entryNode: Node = this.entryN.asInstanceOf[Node]

  var icfg: InterProceduralControlFlowGraph[ICFGNode] = _

	def initGraph(global: Global, icfg: InterProceduralControlFlowGraph[ICFGNode]): Unit = {
    this.icfg = icfg
	  icfg.nodes.foreach {
			case en: ICFGEntryNode =>
				val owner = global.getMethod(en.getOwner).get
				owner.thisOpt match {
					case Some(t) =>
						val n = addIDDGEntryParamNode(en, 0)
						n.asInstanceOf[IDDGEntryParamNode].paramName = t
					case None =>
				}
				val pnames = owner.getParamNames
				for (i <- pnames.indices) {
					val n = addIDDGEntryParamNode(en, i + 1)
					n.asInstanceOf[IDDGEntryParamNode].paramName = pnames(i)
				}
			case en: ICFGExitNode =>
				val owner = global.getMethod(en.getOwner).get
				owner.thisOpt match {
					case Some(t) =>
						val n = addIDDGExitParamNode(en, 0)
						n.asInstanceOf[IDDGExitParamNode].paramName = t
					case None =>
				}
				val pnames = owner.getParamNames
				for (i <- pnames.indices) {
					val n = addIDDGExitParamNode(en, i + 1)
					n.asInstanceOf[IDDGExitParamNode].paramName = pnames(i)
				}
			case cn: ICFGCenterNode =>
				addIDDGCenterNode(cn)
			case cn: ICFGCallNode =>
				cn.recvNameOpt match {
					case Some(recv) =>
						val n = addIDDGCallArgNode(cn, 0)
						n.asInstanceOf[IDDGCallArgNode].argName = recv
					case None =>
				}
				for (i <- cn.argNames.indices) {
					val argName = cn.argNames(i)
					val n = addIDDGCallArgNode(cn, i + 1)
					n.asInstanceOf[IDDGCallArgNode].argName = argName
				}
				val succs = icfg.successors(cn)
				if (succs.exists { succ => succ.isInstanceOf[ICFGReturnNode] }) {
					val vn = addIDDGVirtualBodyNode(cn)
					vn.asInstanceOf[IDDGVirtualBodyNode].argNames = (cn.recvNameOpt ++ cn.argNames).toList
				}
			case rn: ICFGReturnNode =>
				rn.retNameOpt match {
					case Some(name) =>
						val rvn = addIDDGReturnVarNode(rn)
						rvn.asInstanceOf[IDDGReturnVarNode].retVarName = name
					case None =>
				}
				rn.recvNameOpt match {
					case Some(recv) =>
						val n = addIDDGReturnArgNode(rn, 0)
						n.asInstanceOf[IDDGReturnArgNode].argName = recv
					case None =>
				}
				for (i <- rn.argNames.indices) {
					val argName = rn.argNames(i)
					val n = addIDDGReturnArgNode(rn, i + 1)
					n.asInstanceOf[IDDGReturnArgNode].argName = argName
				}
			case nn: ICFGNormalNode => addIDDGNormalNode(nn)
			case _ =>
		}
    this.entryN = addIDDGEntryNode(icfg.entryNode.asInstanceOf[ICFGEntryNode]).asInstanceOf[IDDGEntryNode]
	}
}
