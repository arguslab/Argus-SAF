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
import org.argus.jawa.alir.pta.{FieldSlot, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.{JawaClass, JawaMethod, JawaType}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ListModel {
  def isList(r: JawaClass): Boolean = {
    if(r.isApplicationClass) false
    else {
      val list = r.global.getClassOrResolve(new JawaType("java.util.List"))
      r.global.getClassHierarchy.getAllImplementersOf(list.getType).contains(r.getType)
    }
  }
    
  private def addItemToListField(s: PTAResult, args: List[String], itempar: Int, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.size > 1)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValues = s.pointsToSet(thisSlot, currentContext)
    val paramSlot = VarSlot(args(itempar), isBase = false, isArg = true)
    val paramValues = s.pointsToSet(paramSlot, currentContext)
    thisValues.foreach{
      ins =>
        newfacts ++= paramValues.map{p=> new RFAFact(FieldSlot(ins, "items"), p)}
    }
    newfacts 
  }
  
  private def getListToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val itemSlots = thisValue.map{s => FieldSlot(s, "items")}
    itemSlots.foreach{
      islot =>
        newfacts ++= s.pointsToSet(islot, currentContext).map(ins => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), ins))
    }
    newfacts
  }
  
  private def cloneListToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    thisValue.map{s => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), s.clone(currentContext))}
  }
  
  def doListCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.getSubSignature match{
      case "containsAll:(Ljava/util/Collection;)Z" =>
      case "add:(ILjava/lang/Object;)V" =>
        newFacts ++= addItemToListField(s, args, 2, currentContext)
        byPassFlag = false
      case "equals:(Ljava/lang/Object;)Z" =>
      case "add:(Ljava/lang/Object;)Z" =>
        newFacts ++= addItemToListField(s, args, 1, currentContext)
        byPassFlag = false
      case "addAll:(ILjava/util/Collection;)Z" =>
      case "hashCode:()I" =>
      case "clear:()V" =>
      case "contains:(Ljava/lang/Object;)Z" =>
      case "lastIndexOf:(Ljava/lang/Object;)I" =>
      case "remove:(Ljava/lang/Object;)Z" =>
      case "set:(ILjava/lang/Object;)Ljava/lang/Object;" =>
        newFacts ++= addItemToListField(s, args, 2, currentContext)
        byPassFlag = false
      case "retainAll:(Ljava/util/Collection;)Z" =>
      case "iterator:()Ljava/util/Iterator;" =>
      case "get:(I)Ljava/lang/Object;" =>
        newFacts ++= getListToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "subList:(II)Ljava/util/List;" =>
        newFacts ++= cloneListToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "listIterator:(I)Ljava/util/ListIterator;" =>
      case "isEmpty:()Z" =>
      case "toArray:([Ljava/lang/Object;)[Ljava/lang/Object;" =>
      case "listIterator:()Ljava/util/ListIterator;" =>
      case "size:()I" =>
      case "indexOf:(Ljava/lang/Object;)I" =>
      case "toArray:()[Ljava/lang/Object;" =>
      case "removeAll:(Ljava/util/Collection;)Z" =>
      case "remove:(I)Ljava/lang/Object;" =>
      case "addAll:(Ljava/util/Collection;)Z" =>
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
}
