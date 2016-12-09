/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{JawaClass, JawaMethod, JawaType}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object MapModel {
  def isMap(r: JawaClass): Boolean = {
    if(r.isApplicationClass) false
    else {
      val map = r.global.getClassOrResolve(new JawaType("java.util.Map"))
      val res = r.global.getClassHierarchy.getAllImplementersOf(map.getType).contains(r.getType)
      res
    }
  }

//  private def getPointStringToRet(retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): RFAFact = {
//    val newThisValue = PTAPointStringInstance(currentContext.copy)
//    new RFAFact(VarSlot(retVar, isBase = false, isArg = false), newThisValue)
//  }

  private def cloneMap(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    thisValue.map{s => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), s.clone(currentContext))}
  }
  
  private def getMapEntrySetFactToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val strValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, "entrys"), currentContext)}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.util.HashSet"), retVar, currentContext).get
    result += rf
    result ++= strValue.map{s => new RFAFact(FieldSlot(rf.v, "items"), s)}
    result
  }
  
  private def getMapKeySetToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val strValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, "entrys"), currentContext)}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.util.HashSet"), retVar, currentContext).get
    result += rf
    strValue.foreach {
      case instance: PTATupleInstance => result += new RFAFact(FieldSlot(rf.v, "items"), instance.left)
      case _ =>
    }
    result
  }
  
  private def getMapValuesToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val strValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, "entrys"), currentContext)}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.util.HashSet"), retVar, currentContext).get
    result += rf
    result ++= strValue.map{
      s => 
        require(s.isInstanceOf[PTATupleInstance])
        new RFAFact(FieldSlot(rf.v, "items"), s.asInstanceOf[PTATupleInstance].right)
    }
    result
  }
  
  private def getMapValue(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    val result = msetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val keySlot = VarSlot(args(1), isBase = false, isArg = true)
    val keyValue = s.pointsToSet(keySlot, currentContext)
    if(thisValue.nonEmpty){
      val entValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, "entrys"), currentContext)}.fold(isetEmpty)(iunion[Instance])
      entValue.foreach{
        v =>
          require(v.isInstanceOf[PTATupleInstance])
          if(keyValue.exists { kIns => kIns === v.asInstanceOf[PTATupleInstance].left }){
            result += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v.asInstanceOf[PTATupleInstance].right)
          }
      }
    }
    result.toSet
  } 
  
  private def putMapValue(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    val result = msetEmpty[RFAFact]
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val keySlot = VarSlot(args(1), isBase = false, isArg = true)
    val keyValue = s.pointsToSet(keySlot, currentContext)
    val valueSlot = VarSlot(args(2), isBase = false, isArg = true)
    val valueValue = s.pointsToSet(valueSlot, currentContext)
    val entrys = msetEmpty[Instance]
    keyValue.foreach{
      kv =>
        valueValue.foreach{
          vv =>
            thisValue.foreach{
              ins => entrys += PTATupleInstance(kv, vv, ins.defSite)
            }
        }
    }
    thisValue.foreach{
      ins =>
        result ++= entrys.map(e => new RFAFact(FieldSlot(ins, "entrys"), e))
    }
    result.toSet
  }
  
  private def putAllMapValues(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val slot2 = VarSlot(args(1), isBase = false, isArg = true)
    val value2 = s.pointsToSet(slot2, currentContext)
    thisValue.foreach{
      ins =>
        value2.foreach{
          e => 
            val ents = s.pointsToSet(FieldSlot(e, "entrys"), currentContext)
            result ++= ents.map(new RFAFact(FieldSlot(ins, "entrys"), _))
        }
    }
    result
  }
  
  def doMapCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.getSubSignature match{
      case "clear:()V" =>
      case "clone:()Ljava/lang/Object;" =>
        require(retVars.size == 1)
        newFacts ++= cloneMap(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "entrySet:()Ljava/util/Set;" =>
        require(retVars.size == 1)
        newFacts ++= getMapEntrySetFactToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "get:(Ljava/lang/Object;)Ljava/lang/Object;" =>
        require(retVars.size == 1)
        newFacts ++= getMapValue(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "keySet:()Ljava/util/Set;" =>
        require(retVars.size == 1)
        newFacts ++= getMapKeySetToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" =>
        newFacts ++= putMapValue(s, args, currentContext)
        byPassFlag = false
      case "putAll:(Ljava/util/Map;)V" =>
        newFacts ++= putAllMapValues(s, args, currentContext)
        byPassFlag = false
      case "remove:(Ljava/lang/Object;)Ljava/lang/Object;" =>
        require(retVars.size == 1)
        newFacts ++= getMapValue(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "values:()Ljava/util/Collection;" =>
        require(retVars.size == 1)
        newFacts ++= getMapValuesToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
}
