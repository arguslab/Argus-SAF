/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow

import org.argus.jawa.flow.cfg.{CFGNode, ControlFlowGraph, IntraProceduralControlFlowGraph}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.flow.rda.{JawaDefRef, ReachingDefinitionAnalysis}
import org.argus.jawa.core.ast.{CatchClause, ExceptionCenter, MethodDeclaration, ResolvedBody}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object JawaAlirInfoProvider {
  
  final val CFG = "cfg"
  final val RDA = "rda"
  final val RDA_WITH_CALL = "rda_with_call"
  
  //for building cfg
  def siff(body: ResolvedBody, global: Global): ControlFlowGraph.ShouldIncludeFlowFunction =
    { (loc, catchClauses) =>
      	var result = isetEmpty[CatchClause]
      	val thrownExcs = ExceptionCenter.getExceptionsMayThrow(body, loc, catchClauses.toSet)
      	thrownExcs.foreach{ thrownException =>
          val child = global.getClassOrResolve(thrownException)
          val ccOpt =
            catchClauses.filter{ catchClause =>
              val excType = catchClause.typ.typ
              val exc = global.getClassOrResolve(excType)
              global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(child, exc)
            }
          result ++= ccOpt
      	}
      	(result, false)
    }

  def buildCfg(md: MethodDeclaration, global: Global): IntraProceduralControlFlowGraph[CFGNode] = {
	  val ENTRY_NODE_LABEL = "Entry"
	  val EXIT_NODE_LABEL = "Exit"
	  ControlFlowGraph(md, ENTRY_NODE_LABEL, EXIT_NODE_LABEL, siff(md.resolvedBody, global))
	}
	
	private def buildRda (md: MethodDeclaration, cfg: IntraProceduralControlFlowGraph[CFGNode], initialFacts: ISet[ReachingDefinitionAnalysis.RDFact] = isetEmpty, callRef: Boolean) = {
	  ReachingDefinitionAnalysis(md, cfg, new JawaDefRef(callRef), initialFacts)
	}
	
	/**
   * get cfg of current procedure
   */
  def getCfg(p: JawaMethod): IntraProceduralControlFlowGraph[CFGNode] = {
    if(!(p ? CFG)){
      this.synchronized{
	      val cfg = buildCfg(p.getBody, p.declaringClass.global)
	      p.setProperty(CFG, cfg)
      }
    }
    p.getProperty(CFG)
  }
	
	/**
   * get rda result of current procedure
   */
  def getRda(p: JawaMethod, cfg: IntraProceduralControlFlowGraph[CFGNode]): ReachingDefinitionAnalysis.Result = {
    if(!(p ? RDA)){
      this.synchronized{
	      val rda = buildRda(p.getBody, cfg, callRef = false)
	      p.setProperty(RDA, rda)
      }
    }
    p.getProperty(RDA)
  }

  /**
   * get rda result of current procedure
   */
  def getRdaWithCall(p: JawaMethod, cfg: IntraProceduralControlFlowGraph[CFGNode]): ReachingDefinitionAnalysis.Result = {
    if(!(p ? RDA_WITH_CALL)){
      this.synchronized{
        val rda = buildRda(p.getBody, cfg, callRef = true)
        p.setProperty(RDA_WITH_CALL, rda)
      }
    }
    p.getProperty(RDA_WITH_CALL)
  }
}

case class TransformIntraMethodResult(md: MethodDeclaration, cfg: ControlFlowGraph[CFGNode], rda: ReachingDefinitionAnalysis.Result)
