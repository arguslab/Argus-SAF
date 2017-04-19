/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir

import org.argus.jawa.alir.controlFlowGraph.{CFGNode, ControlFlowGraph, IntraProceduralControlFlowGraph}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.alir.reachingDefinitionAnalysis.{JawaDefRef, ReachingDefinitionAnalysis}
import org.argus.jawa.compiler.parser.{CatchClause, MethodDeclaration, ResolvedBody}

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
      	thrownExcs.foreach{
      	  thrownException =>
          val child = global.getClassOrResolve(thrownException)
      	    val ccOpt =
              catchClauses.find{
			          catchClause =>
			            val excType = catchClause.typ.typ
			            val exc = global.getClassOrResolve(excType)
                  global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(child.getType, exc.getType)
	      	    }
          result ++= ccOpt
      	}
      	
      	(result, false)
    }

  private def buildCfg(md: MethodDeclaration, global: Global): IntraProceduralControlFlowGraph[CFGNode] = {
	  val ENTRY_NODE_LABEL = "Entry"
	  val EXIT_NODE_LABEL = "Exit"
    val rb = md.resolvedBody
	  ControlFlowGraph(rb, ENTRY_NODE_LABEL, EXIT_NODE_LABEL, siff(rb, global))
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
   * get cfg of given method body
   */
  def getCfg(md: MethodDeclaration, global: Global): IntraProceduralControlFlowGraph[CFGNode] = {
    this.synchronized{
      buildCfg(md, global)
    }
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