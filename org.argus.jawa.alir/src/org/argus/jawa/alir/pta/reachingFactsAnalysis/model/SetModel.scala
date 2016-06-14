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
import org.argus.jawa.alir.pta.{FieldSlot, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.{JawaClass, JawaMethod, JawaType}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object SetModel {
  def isSet(r: JawaClass): Boolean = {
    if(r.isApplicationClass) false
    else {
      val set = r.global.getClassOrResolve(new JawaType("java.util.Set"))
      r.global.getClassHierarchy.getAllImplementersOf(set).contains(r)  
    }
  }
    
  private def addItemToSetField(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    require(args.size > 1)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValues = s.pointsToSet(thisSlot, currentContext)
    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramValues = s.pointsToSet(paramSlot, currentContext)
    thisValues.foreach{
      ins =>
        newfacts ++= paramValues.map{p=> new RFAFact(FieldSlot(ins, "items"), p)}
    }
    newfacts 
  }
  
  private def cloneSetToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    thisValue.map{s => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), s.clone(currentContext))}
  }
  
  def doSetCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.getSubSignature match{
      case "add:(Ljava/lang/Object;)Z" =>
        newFacts ++= addItemToSetField(s, args, currentContext)
        byPassFlag = false
      case "clear:()V" =>
      case "clone:()Ljava/lang/Object;" =>
        require(retVars.size == 1)
        newFacts ++= cloneSetToRet(s, args, retVars.head, currentContext)
        byPassFlag = false
      case "contains:(Ljava/lang/Object;)Z" =>
//      case "Ljava/util/HashSet;.createBackingMap:(IF)Ljava/util/HashMap;" =>
//        require(retVars.size == 1)
//        ReachingFactsAnalysisHelper.getReturnFact(ObjectType("java.util.HashMap", 0), retVars(0), currentContext) match{
//          case Some(fact) => newFacts += fact
//          case None =>
//        }
//        byPassFlag = false
      case "isEmpty:()Z" =>
      case "iterator:()Ljava/util/Iterator;" =>
      case "readObject:(Ljava/io/ObjectInputStream;)V" =>
      case "remove:(Ljava/lang/Object;)Z" =>
      case "size:()I" =>
      case "writeObject:(Ljava/io/ObjectOutputStream;)V" =>
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
}
