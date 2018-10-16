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

import org.argus.jawa.core.ast._
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
            case vne: VariableNameExpression =>
              result += VarSlot(vne.name)
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
      val args = j.rhs.varSymbols
      args.map{arg => refCache.getOrElseUpdate(arg, getRefs(arg))}
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
