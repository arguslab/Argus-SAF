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
import org.argus.jawa.alir.controlFlowGraph.{CFGNode, IntraProceduralControlFlowGraph}
import org.argus.jawa.alir.reachingDefinitionAnalysis.{DefDesc, LocDefDesc, ReachingDefinitionAnalysis, Slot}
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ExplicitValueFinder {
  def findExplicitIntValueForArgs(procedure: JawaMethod, cs: CallStatement, l: Location, argNum: Int): ISet[Int] = {
    val cfg = JawaAlirInfoProvider.getCfg(procedure)
    val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
    val params = (cs.recvOpt ++ cs.args).toList
    traverseRdaToFindIntger(procedure, params(argNum), l, cfg, rda)
  }
  
  private def traverseRdaToFindIntger(procedure: JawaMethod, varName: String, loc: Location, cfg: IntraProceduralControlFlowGraph[CFGNode], rda: ReachingDefinitionAnalysis.Result, resolvedStack: ISet[(Slot, DefDesc)] = isetEmpty): ISet[Int] = {
    val slots = rda.entrySet(cfg.getNode(loc.locationUri, loc.locationIndex)) -- resolvedStack
    var nums: ISet[Int] = isetEmpty
    slots.foreach{
      case(slot, defDesc) =>
        if(varName.equals(slot.toString)){
          defDesc match {
            case ldd: LocDefDesc => 
              val locDecl = procedure.getBody.resolvedBody.locations(ldd.locIndex)
              findIntegerFromLocationDecl(varName, locDecl) match{
                case Left(num) => nums += num
                case Right(varn) => nums ++= traverseRdaToFindIntger(procedure, varn, locDecl, cfg, rda, resolvedStack ++ slots)
              }
            case _ =>
          }
        }
    }
    nums
  }
  
  private def findIntegerFromLocationDecl(varName: String, locDecl: Location): Either[Int, String] = {
    var result: Either[Int, String] = Right(varName)
    locDecl.statement match{
      case as: AssignmentStatement =>
        as.rhs match{
          case lExp: LiteralExpression =>
            if(lExp.isInt) result = Left(lExp.getInt)
          case ne: NameExpression =>
            result = Right(ne.name)
          case _ =>
        }
      case _ =>
    }
    result
  }
  
  
  def findExplicitStringValueForArgs(procedure: JawaMethod, cs: CallStatement, l: Location, argNum: Int): ISet[String] = {
      val cfg = JawaAlirInfoProvider.getCfg(procedure)
      val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
      val slots = rda.entrySet(cfg.getNode(l.locationUri, l.locationIndex))
      val strs: MSet[String] = msetEmpty
      slots.foreach{
        case(slot, defDesc) =>
          val varName = cs.arg(argNum)
          if(varName.equals(slot.toString)){
            defDesc match {
              case ldd: LocDefDesc =>
                val locDecl = procedure.getBody.resolvedBody.locations(ldd.locIndex)
                getStringFromLocationDecl(locDecl) match{
                  case Some(str) => strs += str
                  case None => throw new RuntimeException("Cannot find string for: " + varName + ".in:" + l.locationUri)
                }
              case _ =>
            }
          }
      }
      strs.toSet
    
  }
  
  def getStringFromLocationDecl(locDecl: Location): Option[String] = {
    locDecl.statement match{
      case as: AssignmentStatement =>
        as.rhs match{
          case lExp: LiteralExpression =>
            if(lExp.isString) return Some(lExp.getString)
          case _ =>
        }
      case _ =>
    }
    None
  }
  
}
