/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.util

import org.argus.jawa.alir.JawaAlirInfoProvider
import org.argus.jawa.core.JawaMethod
import org.sireum.alir.{ControlFlowGraph, LocDefDesc, ReachingDefinitionAnalysis}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ExplicitValueFinder {
  def findExplicitIntValueForArgs(procedure: JawaMethod, loc: JumpLocation, argNum: Int): ISet[Int] = {
    loc.jump match{
      case t: CallJump if t.jump.isEmpty =>
        val cfg = JawaAlirInfoProvider.getCfg(procedure)
        val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
        val params = t.callExp.arg match {
          case te: TupleExp =>
            te.exps.map{exp=>exp.asInstanceOf[NameExp].name.name}
          case a =>
            throw new RuntimeException("wrong call exp type: " + a)
        }
        traverseRdaToFindIntger(procedure, params(argNum), loc, cfg, rda)
      case _ => throw new RuntimeException("Unexpected jump type: " + loc.jump)
    }
  }
  
  def traverseRdaToFindIntger(procedure: JawaMethod, varName: String, loc: LocationDecl, cfg: ControlFlowGraph[String], rda: ReachingDefinitionAnalysis.Result, resolvedStack: ISet[(org.sireum.alir.Slot, org.sireum.alir.DefDesc)] = isetEmpty): ISet[Int] = {
    val slots = rda.entrySet(cfg.getNode(Some(loc.name.get.uri), loc.index)) -- resolvedStack
    var nums: ISet[Int] = isetEmpty
    slots.foreach{
      case(slot, defDesc) =>
        if(varName.equals(slot.toString)){
          defDesc match {
            case ldd: LocDefDesc => 
              val locDecl = procedure.getBody.location(ldd.locIndex)
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
  
  private def findIntegerFromLocationDecl(varName: String, locDecl: LocationDecl): Either[Int, String] = {
    var result: Either[Int, String] = Right(varName)
    locDecl match{
      case aLoc: ActionLocation =>
        aLoc.action match{
          case assignAction: AssignAction =>
            assignAction.rhs match{
              case lExp: LiteralExp =>
                if(lExp.typ == LiteralType.INT) result = Left(lExp.literal.asInstanceOf[Int])
              case ne: NameExp =>
                result = Right(ne.name.name)
              case a =>
            }
          case _ =>
        }
      case _ =>
    }
    result
  }
  
  
  def findExplicitStringValueForArgs(procedure: JawaMethod, loc: JumpLocation, argNum: Int): ISet[String] = {
    loc.jump match{
      case t: CallJump if t.jump.isEmpty =>
        val cfg = JawaAlirInfoProvider.getCfg(procedure)
        val rda = JawaAlirInfoProvider.getRda(procedure, cfg)
        val slots = rda.entrySet(cfg.getNode(Some(loc.name.get.uri), loc.index))
        val params = t.callExp.arg match {
          case te: TupleExp =>
            te.exps.map{exp=>exp.asInstanceOf[NameExp].name.name}
          case a =>
            throw new RuntimeException("wrong call exp type: " + a)
        }
        var strs: ISet[String] = isetEmpty
        slots.foreach{
          case(slot, defDesc) =>
            val varName = params(argNum)
            if(varName.equals(slot.toString)){
              defDesc match {
                case ldd: LocDefDesc => 
//                  val node = cfg.getNode(ldd.locUri, ldd.locIndex)
                  val locDecl = procedure.getBody.location(ldd.locIndex)
                  getStringFromLocationDecl(locDecl) match{
                    case Some(str) => strs += str
                    case None => throw new RuntimeException("Cannot find intgerNumber for: " + varName + ".in:" + loc.name.get.uri)
                  }
                case _ =>
              }
            }
        }
        strs
      case _ => throw new RuntimeException("Unexpected jump type: " + loc.jump)
    }
    
  }
  
  def getStringFromLocationDecl(locDecl: LocationDecl): Option[String] = {
    locDecl match{
      case aLoc: ActionLocation =>
        aLoc.action match{
          case assignAction: AssignAction =>
            assignAction.rhs match{
              case lExp: LiteralExp =>
                if(lExp.typ == LiteralType.STRING) return Some(lExp.text)
              case _ =>
            }
          case _ =>
        }
      case _ =>
    }
    None
  }
  
}
