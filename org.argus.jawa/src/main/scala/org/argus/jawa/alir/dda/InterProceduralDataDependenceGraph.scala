/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.dda

import org.argus.jawa.alir.cfg._
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
				var position = 0
				owner.thisOpt match {
					case Some(t) =>
						val n = addIDDGEntryParamNode(en, position)
						n.asInstanceOf[IDDGEntryParamNode].paramName = t
					case None =>
				}
				position += 1
				val pnames = owner.getParamNames
				for (i <- pnames.indices) {
					val n = addIDDGEntryParamNode(en, position)
					n.asInstanceOf[IDDGEntryParamNode].paramName = pnames(i)
					position += 1
				}
			case en: ICFGExitNode =>
				val owner = global.getMethod(en.getOwner).get
				var position = 0
				owner.thisOpt match {
					case Some(t) =>
						val n = addIDDGExitParamNode(en, position)
						n.asInstanceOf[IDDGExitParamNode].paramName = t
					case None =>
				}
				position += 1
				val pnames = owner.getParamNames
				for (i <- pnames.indices) {
					val n = addIDDGExitParamNode(en, position)
					n.asInstanceOf[IDDGExitParamNode].paramName = pnames(i)
					position += 1
				}
			case cn: ICFGCenterNode =>
				addIDDGCenterNode(cn)
			case cn: ICFGCallNode =>
				val inc = if(cn.getCallType == "static") 1 else 0
				for (i <- cn.argNames.indices) {
					val argName = cn.argNames(i)
					val n = addIDDGCallArgNode(cn, i + inc)
					n.asInstanceOf[IDDGCallArgNode].argName = argName
				}
				val succs = icfg.successors(cn)
				if (succs.exists { succ => succ.isInstanceOf[ICFGReturnNode] }) {
					val vn = addIDDGVirtualBodyNode(cn)
					vn.asInstanceOf[IDDGVirtualBodyNode].argNames = cn.argNames
				}
			case rn: ICFGReturnNode =>
				rn.retNameOpt match {
					case Some(name) =>
						val rvn = addIDDGReturnVarNode(rn)
						rvn.asInstanceOf[IDDGReturnVarNode].retVarName = name
					case None =>
				}
				val inc = if(rn.getCallType == "static") 1 else 0
				for (i <- rn.argNames.indices) {
					val argName = rn.argNames(i)
					val n = addIDDGReturnArgNode(rn, i + inc)
					n.asInstanceOf[IDDGReturnArgNode].argName = argName
				}
			case nn: ICFGNormalNode => addIDDGNormalNode(nn)
			case _ =>
		}
    this.entryN = addIDDGEntryNode(icfg.entryNode.asInstanceOf[ICFGEntryNode]).asInstanceOf[IDDGEntryNode]
	}
}
