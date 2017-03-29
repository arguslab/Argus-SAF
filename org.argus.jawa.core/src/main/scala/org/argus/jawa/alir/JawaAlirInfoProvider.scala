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

import org.argus.jawa.core._
import org.sireum.alir.{AlirIntraProceduralGraph, DefRef, ControlFlowGraph => OrigControlFlowGraph}
import org.sireum.util._
import org.sireum.pilar.symbol.SymbolTable
import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.pilar.ast.CatchClause
import org.sireum.pilar.ast.NamedTypeSpec
import org.sireum.pilar.ast.Model
import org.sireum.pilar.ast.NameExp
import org.argus.jawa.alir.controlFlowGraph.{ControlFlowGraph => JawaControlFlowGraph}
import org.argus.jawa.alir.reachingDefinitionAnalysis.{JawaDefRef, JawaReachingDefinitionAnalysis, JawaVarAccesses}
import org.argus.jawa.core.symbolResolver.JawaSymbolTableBuilder
import org.sireum.pilar.parser.PilarParser.ErrorReporter

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object JawaAlirInfoProvider {
  
  final val CFG = "cfg"
  final val RDA = "rda"
  final val RDA_WITH_CALL = "rda_with_call"
  
  //for building cfg
  type VirtualLabel = String
  
  var dr: (SymbolTable, Boolean) => DefRef = { (st, b) => new JawaDefRef(st, new JawaVarAccesses(st), b) }
  
  val iopp: ProcedureSymbolTable => (ResourceUri => Boolean, ResourceUri => Boolean) = { pst =>
    val params = pst.params.toSet[ResourceUri]
    ({ localUri => params.contains(localUri) },
      { s => falsePredicate1[ResourceUri](s) })
  }
  
  val saom: Boolean = true
  
  def init(dr: (SymbolTable, Boolean) => DefRef): Unit = {
    this.dr = dr
  }
  
  protected[jawa] def getExceptionType(cc: CatchClause): JawaType = {
    require(cc.typeSpec.isDefined)
    require(cc.typeSpec.get.isInstanceOf[NamedTypeSpec])
    val name = cc.typeSpec.get.asInstanceOf[NamedTypeSpec].name.name
    new JawaType(name)
  }
  
  //for building cfg
  def siff(pst: ProcedureSymbolTable, global: Global): OrigControlFlowGraph.ShouldIncludeFlowFunction =
    { (loc, catchclauses) => 
      	var result = isetEmpty[CatchClause]
      	val thrownExcs = ExceptionCenter.getExceptionsMayThrow(pst, loc, catchclauses.toSet)
      	thrownExcs.foreach{
      	  thrownException =>
          val child = global.getClassOrResolve(thrownException)
      	    val ccOpt = 
	      	    catchclauses.find{
			          catchclause =>
			            val excType = getExceptionType(catchclause)
			            val exc = global.getClassOrResolve(excType)
                  exc.global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(child.getType, exc.getType)
	      	    }
          result ++= ccOpt
      	}
      	
      	(result, false)
    }
  
  def reporter: ErrorReporter = {
	  new org.sireum.pilar.parser.PilarParser.ErrorReporter {
      def report(source: Option[FileResourceUri], line: Int,
                 column: Int, message: String): Unit =
        System.err.println("source:" + source + ".line:" + line + ".column:" + column + ".message:" + message)
    }
	}
  
	def getIntraMethodResult(code: String, global: Global): Map[ResourceUri, TransformIntraMethodResult] = {
	  val newModel = JawaResolver.parseCodes(Set(code))
	  doGetIntraMethodResult(newModel, global)
	}
	
	def getIntraMethodResult(codes: Set[String], global: Global): Map[ResourceUri, TransformIntraMethodResult] = {
	  val newModel = JawaResolver.parseCodes(codes)
	  doGetIntraMethodResult(newModel, global)
	}
	
	private def doGetIntraMethodResult(model: Model, global: Global): Map[ResourceUri, TransformIntraMethodResult] = {
	  val result = JawaSymbolTableBuilder(List(model), JawaResolver.fst, parallel = false)
	  result.procedureSymbolTables.map{
	    pst=>
	      val (_, cfg) = buildCfg(pst, global)
	      val rda = buildRda(pst, cfg, callref = false)
	      val procSig = 
	        pst.procedure.getValueAnnotation("signature") match {
			      case Some(exp: NameExp) =>
			        exp.name.name
			      case _ => throw new RuntimeException("Can not find signature")
			    }
	      (procSig, TransformIntraMethodResult(pst, cfg, rda))
	  }.toMap
	}
  
  private def buildCfg(pst: ProcedureSymbolTable, global: Global) = {
	  val ENTRY_NODE_LABEL = "Entry"
	  val EXIT_NODE_LABEL = "Exit"
	  val pool: AlirIntraProceduralGraph.NodePool = mmapEmpty
	  val result = JawaControlFlowGraph[VirtualLabel](pst, ENTRY_NODE_LABEL, EXIT_NODE_LABEL, pool, siff(pst, global))
	  (pool, result)
	}
	
	private def buildRda (pst: ProcedureSymbolTable, cfg: OrigControlFlowGraph[VirtualLabel], initialFacts: ISet[JawaReachingDefinitionAnalysis.RDFact] = isetEmpty, callref: Boolean) = {
	  val iiopp = iopp(pst)
	  JawaReachingDefinitionAnalysis[VirtualLabel](pst,
	    cfg,
	    dr(pst.symbolTable, callref),
	    first2(iiopp),
	    saom,
	    initialFacts)
	}
	
	/**
   * get cfg of current procedure
   */
  def getCfg(p: JawaMethod): OrigControlFlowGraph[VirtualLabel] = {
    if(!(p ? CFG)){
      this.synchronized{
	      val cfg = buildCfg(p.getBody, p.declaringClass.global)._2
	      p.setProperty(CFG, cfg)
      }
    }
    p.getProperty(CFG)
  }
  
  /**
   * get cfg of given method body
   */
  def getCfg(md: MethodBody, global: Global): OrigControlFlowGraph[VirtualLabel] = {
    this.synchronized{
      buildCfg(md, global)._2
    }
  }
	
	/**
   * get rda result of current procedure
   */
  def getRda(p: JawaMethod, cfg: OrigControlFlowGraph[VirtualLabel]): JawaReachingDefinitionAnalysis.Result = {
    if(!(p ? RDA)){
      this.synchronized{
	      val rda = buildRda(p.getBody, cfg, callref = false)
	      p.setProperty(RDA, rda)
      }
    }
    p.getProperty(RDA)
  }

  /**
   * get rda result of current procedure
   */
  def getRdaWithCall(p: JawaMethod, cfg: OrigControlFlowGraph[VirtualLabel]): JawaReachingDefinitionAnalysis.Result = {
    if(!(p ? RDA_WITH_CALL)){
      this.synchronized{
        val rda = buildRda(p.getBody, cfg, callref = true)
        p.setProperty(RDA_WITH_CALL, rda)
      }
    }
    p.getProperty(RDA_WITH_CALL)
  }
}

case class TransformIntraMethodResult(pst: ProcedureSymbolTable, cfg: OrigControlFlowGraph[String], rda: JawaReachingDefinitionAnalysis.Result)
