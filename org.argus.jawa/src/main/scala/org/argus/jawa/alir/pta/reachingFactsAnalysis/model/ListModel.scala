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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.core.{Constants, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ListModel extends ModelCall {
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val list = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.LIST))
      p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(list).contains(p.getDeclaringClass)
    }
  }
    
  private def addItemToListField(s: PTAResult, args: List[String], itempar: Int, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.size > 1)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head)
    val thisValues = s.pointsToSet(after = false, currentContext, thisSlot)
    val paramSlot = VarSlot(args(itempar))
    val paramValues = s.pointsToSet(after = false, currentContext, paramSlot)
    thisValues.foreach{ ins =>
      newfacts ++= paramValues.map{p=> new RFAFact(FieldSlot(ins, Constants.LIST_ITEMS), p)}
    }
    newfacts 
  }
  
  private def getListToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.nonEmpty)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val itemSlots = thisValue.map{s => FieldSlot(s, Constants.LIST_ITEMS)}
    itemSlots.foreach{ islot =>
      newfacts ++= s.pointsToSet(after = false, currentContext, islot).map(ins => new RFAFact(VarSlot(retVar), ins))
    }
    newfacts
  }
  
  private def cloneListToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    thisValue.map{s => new RFAFact(VarSlot(retVar), s.clone(currentContext))}
  }
  
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
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
        newFacts ++= getListToRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "subList:(II)Ljava/util/List;" =>
        newFacts ++= cloneListToRet(s, args, retVar, currentContext)
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
