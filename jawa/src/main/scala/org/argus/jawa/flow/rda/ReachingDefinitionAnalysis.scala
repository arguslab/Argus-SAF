/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.rda

import org.argus.jawa.flow.cfg.{CFGLocationNode, CFGNode, IntraProceduralControlFlowGraph}
import org.argus.jawa.flow.dfa._
import org.argus.jawa.core.ast._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ReachingDefinitionAnalysis {
  type N = CFGNode
  type RDFact = (Slot, DefDesc)
  type LOC = (String, Int)
  type Result = MonotoneDataFlowAnalysisResult[N, RDFact]
  
  def apply(
      md: MethodDeclaration,
      cfg: IntraProceduralControlFlowGraph[N],
      defRef: DefRef,
      initialFacts: ISet[RDFact] = isetEmpty): Result = build(md, cfg, defRef, initialFacts)

  def build(
      md: MethodDeclaration,
      cfg: IntraProceduralControlFlowGraph[N],
      defRef: DefRef,
      initialFacts: ISet[RDFact]): Result = {
    val ip = new IntraIngredientProvider[RDFact](md, cfg)
    val gen = new Gen(defRef)
    val kill = new Kill(defRef)
    val iota: ISet[RDFact] = {
      val result = msetEmpty[RDFact]
      for(param <- md.thisParam ++ md.paramList) result += ((VarSlot(param.name), InitDefDesc))
      for(local <- md.resolvedBody.locals) result += ((VarSlot(local.varSymbol.varName), UnDefDesc))
      md.resolvedBody.locations foreach { l =>
        l.statement match {
          case as: AssignmentStatement =>
            as.rhs match {
              case ne: StaticFieldAccessExpression =>
                result += ((VarSlot("@@" + ne.name), InitDefDesc))
              case _ =>
            }
          case _ =>
        }
      }
      result ++= initialFacts
      result.toSet
    }
    val initial: ISet[RDFact] = isetEmpty
    val result = MonotoneDataFlowAnalysisFramework[N, RDFact, LOC](cfg, forward = true, lub = true, ip, gen, kill, None, iota, initial)
    result
  }

  protected class Gen(defRef: DefRef)
      extends MonotonicFunction[N, RDFact] {
    private def handleAssignment(s: ISet[RDFact], a: Assignment, currentNode: N): ISet[RDFact] = {
      val ldd = LLocDefDesc(currentNode.asInstanceOf[CFGLocationNode].locUri, currentNode.asInstanceOf[CFGLocationNode].locIndex)
      a match {
        case j: CallStatement =>
          val strongDefs = defRef.strongDefinitions(j)
          val defs = defRef.definitions(j).diff(strongDefs)
          val callDefs = defRef.callDefinitions(j)
          var i = -1
          val paramDefs = callDefs.map { s =>
            i += 1
            s.diff(strongDefs).map { d =>
              (d, ParamDefDesc(ldd.locUri, ldd.locIndex, i)): RDFact
            }
          }.fold(Set[RDFact]())(iunion[RDFact])
          paramDefs.union(defs.map { d =>
            (d, EffectDefDesc(ldd.locUri, ldd.locIndex))
          }) ++ strongDefs.map { d => (d, ldd) }
        case _ =>
          defRef.definitions(a).map { d => (d, ldd) }
      }
    }
    def apply(s: ISet[RDFact], e: Statement, currentNode: N): ISet[RDFact] = {
      e match {
        case a: Assignment => handleAssignment(s, a, currentNode)
        case _ => isetEmpty
      }
    }
  }

  protected class Kill(defRef: DefRef)
      extends MonotonicFunction[N, RDFact] {
    def apply(s: ISet[RDFact], e: Statement, currentNode: N): ISet[RDFact] = {
      e match {
        case a: Assignment =>
          val strongDefs = defRef.strongDefinitions(a)
          var result = s
          for (rdf @ (slot, _) <- s) {
            if (strongDefs.contains(slot)) {
              result = result - rdf
            }
          }
          result
        case _ => s
      }
    }
  }
}
