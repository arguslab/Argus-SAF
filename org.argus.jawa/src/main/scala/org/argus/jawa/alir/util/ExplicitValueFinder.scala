/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.util

import org.argus.jawa.alir.JawaAlirInfoProvider
import org.argus.jawa.alir.cfg.{CFGNode, IntraProceduralControlFlowGraph}
import org.argus.jawa.alir.rda.{DefDesc, LocDefDesc, ReachingDefinitionAnalysis, Slot}
import org.argus.jawa.ast._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ExplicitValueFinder {
  def findExplicitLiteralForArgs(procedure: JawaMethod, l: Location, arg: String): ISet[LiteralExpression] = {
    val cfg = JawaAlirInfoProvider.getCfg(procedure)
    val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
    traverseRdaToFindLiteral(procedure, arg, l, cfg, rda)
  }
  
  private def traverseRdaToFindLiteral(procedure: JawaMethod, varName: String, loc: Location, cfg: IntraProceduralControlFlowGraph[CFGNode], rda: ReachingDefinitionAnalysis.Result, resolvedStack: ISet[(Slot, DefDesc)] = isetEmpty): ISet[LiteralExpression] = {
    val slots = rda.entrySet(cfg.getNode(loc.locationUri, loc.locationIndex)) -- resolvedStack
    var nums: ISet[LiteralExpression] = isetEmpty
    slots.foreach{
      case(slot, defDesc) =>
        if(varName.equals(slot.toString)){
          defDesc match {
            case ldd: LocDefDesc => 
              val locDecl = procedure.getBody.resolvedBody.locations(ldd.locIndex)
              findLiteralFromLocationDecl(varName, locDecl) match{
                case Left(num) => nums += num
                case Right(varn) => nums ++= traverseRdaToFindLiteral(procedure, varn, locDecl, cfg, rda, resolvedStack + ((slot, defDesc)))
              }
            case _ =>
          }
        }
    }
    nums
  }
  
  private def findLiteralFromLocationDecl(varName: String, locDecl: Location): Either[LiteralExpression, String] = {
    var result: Either[LiteralExpression, String] = Right(varName)
    locDecl.statement match{
      case as: AssignmentStatement =>
        as.rhs match{
          case t: LiteralExpression =>
            result = Left(t)
          case ne: NameExpression =>
            result = Right(ne.name)
          case _ =>
        }
      case _ =>
    }
    result
  }

  def isArgStaticBytes(procedure: JawaMethod, l: Location, arg: String): Boolean = {
    val cfg = JawaAlirInfoProvider.getCfg(procedure)
    val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
    traverseRdaToFindByteCreation(procedure, arg, l, cfg, rda)
  }

  private def traverseRdaToFindByteCreation(procedure: JawaMethod, varName: String, loc: Location, cfg: IntraProceduralControlFlowGraph[CFGNode], rda: ReachingDefinitionAnalysis.Result, resolvedStack: ISet[(Slot, DefDesc)] = isetEmpty): Boolean = {
    val slots = rda.entrySet(cfg.getNode(loc.locationUri, loc.locationIndex)) -- resolvedStack
    slots.foreach{
      case(slot, defDesc) =>
        if(varName.equals(slot.toString)){
          defDesc match {
            case ldd: LocDefDesc =>
              val locDecl = procedure.getBody.resolvedBody.locations(ldd.locIndex)
              findByteCreationFromLocationDecl(varName, locDecl) match{
                case Left(b) => return b
                case Right(varn) => return traverseRdaToFindByteCreation(procedure, varn, locDecl, cfg, rda, resolvedStack + ((slot, defDesc)))
              }
            case _ =>
          }
        }
    }
    false
  }

  private def findByteCreationFromLocationDecl(varName: String, locDecl: Location): Either[Boolean, String] = {
    var result: Either[Boolean, String] = Right(varName)
    locDecl.statement match{
      case as: AssignmentStatement =>
        as.rhs match{
          case _: AccessExpression =>
          case _: BinaryExpression =>
            result = Left(true)
          case _: CmpExpression =>
            result = Left(true)
          case _: ExceptionExpression =>
            result = Left(true)
          case _: InstanceofExpression =>
            result = Left(true)
          case _: LengthExpression =>
            result = Left(true)
          case _: LiteralExpression =>
            result = Left(true)
          case ne: NameExpression =>
            result = Right(ne.name)
          case _: TupleExpression =>
            result = Left(true)
          case _: UnaryExpression =>
            result = Left(true)
          case _ =>
        }
      case cs: CallStatement =>
        if(cs.signature.signature == "Ljava/lang/String;.getBytes:()[B") {
          result = Left(true)
        }
      case _ =>
    }
    result
  }
}
