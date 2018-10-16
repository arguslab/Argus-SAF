/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta.suspark

import org.argus.jawa.flow.Context
import org.argus.jawa.core.{JawaMethod, PointBaseR, PointsCollector}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object IntraProceduralSuperSpark {

  def apply(ap: JawaMethod): PointerAssignmentGraph[PtaNode] = build(ap)

  def build(ap: JawaMethod): PointerAssignmentGraph[PtaNode] = {
    val pag = new PointerAssignmentGraph[PtaNode]()
    doPTA(ap, pag)
    pag
  }
  
  def doPTA(ap: JawaMethod,
            pag: PointerAssignmentGraph[PtaNode]): Unit = {
    val points = PointsCollector.points(ap.getSignature, ap.getBody)
    val context: Context = new Context(ap.getDeclaringClass.global.projectName)
    pag.constructGraph(ap, points, context.copy, entryPoint = true)
    workListPropagation(pag)
  }
  
  def workListPropagation(pag: PointerAssignmentGraph[PtaNode]): Unit = {
    pag.edges.foreach{ edge =>
			pag.getEdgeType(edge) match{
				case EdgeType.ALLOCATION =>
					pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
					pag.worklist += edge.target
				case _ =>
			}
    }
    while (pag.worklist.nonEmpty) {
      while (pag.worklist.nonEmpty) {
      	val srcNode = pag.worklist.remove(0)
      	srcNode.point match{
      	  case pbr: PointBaseR => // e.g. q = ofnl.f; edge is ofbnl.f -> q
      	    val fp = pbr.getFieldPoint
            val fNode = pag.getNode(fp, srcNode.context)
      	    pag.successorEdges(fNode).foreach{ edge => //edge is FIELD_LOAD type
							val dstNode = pag.successor(edge)
							if(pag.pointsToMap.isDiff(fNode, dstNode)) pag.worklist += dstNode
							pag.pointsToMap.propagatePointsToSet(fNode, dstNode)
      	    }
      	  case _ =>
      	}
  	    pag.successorEdges(srcNode).foreach{ edge =>
					pag.getEdgeType(edge) match{
						case EdgeType.TRANSFER => // e.g. L0: p = q; L1:  r = p; edge is p@L0 -> p@L1
							val dstNode = pag.successor(edge)
							if(pag.pointsToMap.isDiff(srcNode, dstNode)){
								pag.worklist += dstNode
//      	          val d = pag.pointsToMap.getDiff(srcNode, dstNode)
								pag.pointsToMap.transferPointsToSet(srcNode, dstNode)
							}
						case EdgeType.ASSIGNMENT => // e.g. q = p; Edge: p -> q
							val dstNode = pag.successor(edge)
							if(pag.pointsToMap.isDiff(srcNode, dstNode)){
								pag.worklist += dstNode
								pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
							}
						case EdgeType.FIELD_STORE => // e.g. r.f = q; Edge: q -> r.f
							val dstNode = pag.successor(edge)
							pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
						case EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
							val dstNode = pag.successor(edge)
							if(pag.pointsToMap.isDiff(srcNode, dstNode)){
								pag.worklist += dstNode
								pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
							}
						case EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
							val dstNode = pag.successor(edge)
							if(!pag.pointsToMap.contained(srcNode, dstNode)){
								pag.worklist += dstNode
								pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
							}
						case EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
							val dstNode = pag.successor(edge)
							if(pag.pointsToMap.isDiff(srcNode, dstNode)){
								pag.worklist += dstNode
								pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
							}
						case EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
							val dstNode = pag.successor(edge)
							if(!pag.pointsToMap.contained(srcNode, dstNode)){
								pag.worklist += dstNode
								pag.pointsToMap.propagatePointsToSet(srcNode, dstNode)
							}
						case _ =>
					}
      	}
      }
      pag.edges.foreach{ edge =>
				pag.getEdgeType(edge) match{
					case EdgeType.FIELD_STORE => // q -> r.f
						pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
					case EdgeType.ARRAY_STORE => // e.g. r[i] = q; Edge: q -> r[i]
						if(pag.pointsToMap.pointsToSet(edge.target).nonEmpty
								&& !pag.pointsToMap.contained(edge.source, edge.target)){
							pag.worklist += edge.target
							pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
						}
					case EdgeType.STATIC_FIELD_STORE => // e.g. @@r = q; Edge: q -> @@r
						if(!pag.pointsToMap.contained(edge.source, edge.target)){
							pag.worklist += edge.target
							pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
						}
					case _ =>
				}
	    }
      pag.edges.foreach{ edge =>
				pag.getEdgeType(edge) match{
					case EdgeType.FIELD_LOAD => // p.f -> q
						if(pag.pointsToMap.isDiff(edge.source, edge.target)){
							pag.worklist += edge.target
							pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
						}
					case EdgeType.ARRAY_LOAD => // e.g. q = p[i]; Edge: p[i] -> q
						if(pag.pointsToMap.isDiff(edge.source, edge.target)){
							pag.worklist += edge.target
							pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
						}
					case EdgeType.STATIC_FIELD_LOAD => // e.g. q = @@p; Edge: @@p -> q
							if(pag.pointsToMap.isDiff(edge.source, edge.target)){
								pag.worklist += edge.target
								pag.pointsToMap.propagatePointsToSet(edge.source, edge.target)
							}
					case _ =>
				}
	    }
    }
  }
}
