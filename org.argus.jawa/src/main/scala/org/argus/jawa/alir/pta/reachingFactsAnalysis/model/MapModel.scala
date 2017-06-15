/*
 * Copyright (c) 2017. Fengguo Wei and others.
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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{Constants, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class MapModel extends ModelCall {
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val map = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.MAP))
      val res = p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(map).contains(p.getDeclaringClass)
      res
    }
  }

  private def cloneMap(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    thisValue.map{s => new RFAFact(VarSlot(retVar), s.clone(currentContext))}
  }
  
  private def getMapEntrySetFactToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val strValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, Constants.MAP_ENTRIES))}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType(Constants.HASHSET), retVar, currentContext).get
    result += rf
    result ++= strValue.map{s => new RFAFact(FieldSlot(rf.v, Constants.HASHSET_ITEMS), s)}
    result
  }
  
  private def getMapKeySetToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val strValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, Constants.MAP_ENTRIES))}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType(Constants.HASHSET), retVar, currentContext).get
    result += rf
    strValue.foreach {
      case instance: PTATupleInstance => result += new RFAFact(FieldSlot(rf.v, Constants.HASHSET_ITEMS), instance.left)
      case _ =>
    }
    result
  }
  
  private def getMapValuesToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val strValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, Constants.MAP_ENTRIES))}.fold(isetEmpty)(iunion[Instance])
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType(Constants.HASHSET), retVar, currentContext).get
    result += rf
    result ++= strValue.map{ s =>
      require(s.isInstanceOf[PTATupleInstance])
      new RFAFact(FieldSlot(rf.v, Constants.HASHSET_ITEMS), s.asInstanceOf[PTATupleInstance].right)
    }
    result
  }
  
  private def getMapValue(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    val result = msetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val keySlot = VarSlot(args(1))
    val keyValue = s.pointsToSet(after = false, currentContext, keySlot)
    if(thisValue.nonEmpty){
      val entValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, Constants.MAP_ENTRIES))}.fold(isetEmpty)(iunion[Instance])
      entValue.foreach{ v =>
        require(v.isInstanceOf[PTATupleInstance])
        if(keyValue.exists { kIns => kIns === v.asInstanceOf[PTATupleInstance].left }){
          result += new RFAFact(VarSlot(retVar), v.asInstanceOf[PTATupleInstance].right)
        }
      }
    }
    result.toSet
  } 
  
  private def putMapValue(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    val result = msetEmpty[RFAFact]
    require(args.size >2)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val keySlot = VarSlot(args(1))
    val keyValue = s.pointsToSet(after = false, currentContext, keySlot)
    val valueSlot = VarSlot(args(2))
    val valueValue = s.pointsToSet(after = false, currentContext, valueSlot)
    val entrys = msetEmpty[Instance]
    keyValue.foreach{ kv =>
      valueValue.foreach{ vv =>
        thisValue.foreach{
          ins => entrys += PTATupleInstance(kv, vv, ins.defSite)
        }
      }
    }
    thisValue.foreach{ ins =>
      result ++= entrys.map(e => new RFAFact(FieldSlot(ins, Constants.MAP_ENTRIES), e))
    }
    result.toSet
  }
  
  private def putAllMapValues(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val slot2 = VarSlot(args(1))
    val value2 = s.pointsToSet(after = false, currentContext, slot2)
    thisValue.foreach{ ins =>
      value2.foreach{ e =>
        val ents = s.pointsToSet(after = false, currentContext, FieldSlot(e, Constants.MAP_ENTRIES))
        result ++= ents.map(new RFAFact(FieldSlot(ins, Constants.MAP_ENTRIES), _))
      }
    }
    result
  }
  
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.getSubSignature match{
      case "clear:()V" =>
      case "clone:()Ljava/lang/Object;" =>
        newFacts ++= cloneMap(s, args, retVar, currentContext)
        byPassFlag = false
      case "entrySet:()Ljava/util/Set;" =>
        newFacts ++= getMapEntrySetFactToRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "get:(Ljava/lang/Object;)Ljava/lang/Object;" =>
        newFacts ++= getMapValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "keySet:()Ljava/util/Set;" =>
        newFacts ++= getMapKeySetToRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" =>
        newFacts ++= putMapValue(s, args, currentContext)
        byPassFlag = false
      case "putAll:(Ljava/util/Map;)V" =>
        newFacts ++= putAllMapValues(s, args, currentContext)
        byPassFlag = false
      case "remove:(Ljava/lang/Object;)Ljava/lang/Object;" =>
        newFacts ++= getMapValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "values:()Ljava/util/Collection;" =>
        newFacts ++= getMapValuesToRet(s, args, retVar, currentContext)
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
}
