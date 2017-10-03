/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachingDefinitionAnalysis

import org.argus.jawa.ast._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class JawaDefRef(callRef: Boolean)
  extends DefRef {

  val TITLE = "JawaDefRef"

  def definitions(a: Assignment): ISet[Slot] = {
    strongDefinitions(a)
  }

  def strongDefinitions(a: Assignment): ISet[Slot] =
    defCache.getOrElseUpdate(a, {
      val lhs = a.getLhs
      val result = msetEmpty[Slot]
      lhs match {
        case Some(l) =>
          l match {
            case cl: CallLhs =>
              result += VarSlot(cl.lhs.varName)
            case ne: NameExpression =>
              if(!ne.isStatic) {
                result += VarSlot(ne.name)
              }
            case _ =>
          }
        case None =>
      }
      result.toSet
    })

  def references(j: Jump): ISet[Slot] =
    refCache.getOrElseUpdate(j, getRefs(j))

  def callReferences(j: CallStatement): ISeq[ISet[Slot]] = {
    if(callRef){
      val args = j.rhs.argClause.varSymbols
      args.map{case (arg, _) => refCache.getOrElseUpdate(arg, getRefs(arg))}
    } else ivectorEmpty
  }

  def callDefinitions(j: CallStatement): ISeq[ISet[Slot]] = {
    callReferences(j)
  }

  private def getRefs(n: JawaAstNode): ISet[Slot] = {
    var result = isetEmpty[Slot]
    val lhs = n match {
      case a: Assignment => a.getLhs
      case _ => None
    }
    Visitor.build({
      case ne: VarSymbol =>
        if (!lhs.contains(ne))
          result = result + VarSlot(ne.varName)
        false
    })(n)
    result
  }

  private val defCache = idmapEmpty[Assignment, ISet[Slot]]
  private val refCache = idmapEmpty[JawaAstNode, ISet[Slot]]
}
