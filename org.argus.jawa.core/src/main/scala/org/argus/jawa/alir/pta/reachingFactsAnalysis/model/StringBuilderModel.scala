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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{JawaClass, JawaMethod, JawaType}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object StringBuilderModel {
  
  def isStringBuilder(r: JawaClass): Boolean = r.getName.equals("java.lang.StringBuilder")
  
  private def getReturnFactsWithAlias(rType: JawaType, retVar: String, currentContext: Context, alias: ISet[Instance])(implicit factory: RFAFactFactory): ISet[RFAFact] = 
    alias.map{a=> new RFAFact(VarSlot(retVar, isBase = false, isArg = false), a)}
  
//  private def getPointStringForThis(args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
//    require(args.nonEmpty)
//    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
//      val newThisValue = PTAPointStringInstance(currentContext.copy)
//      Set(new RFAFact(thisSlot, newThisValue))
//  }
//
//  private def getFactFromArgForThis(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
//    require(args.size > 1)
//    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
//    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
//    s.pointsToSet(paramSlot, currentContext).map(v => new RFAFact(thisSlot, v))
//  }
  
  
//  private def getOldFactForThis(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
//    require(args.nonEmpty)
//    val thisSlot = VarSlot(args(0), false, true)
//    s.pointsToSet(thisSlot, currentContext).map(v => new RFAFact(thisSlot, v))
//  }
  
  private def getPointStringForRet(retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.String"), retVar, currentContext) match{
      case Some(fact) =>           
          //deleteFacts += fact
          val value = PTAPointStringInstance(currentContext.copy)
          Set(new RFAFact(fact.s, value))
      case None => isetEmpty
    }
   
  }
  
//  private def getFactFromThisForRet(s: PTAResult, args: List[String], retVarOpt: Option[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
//    require(args.nonEmpty)
//    ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.String"), retVarOpt.get, currentContext) match{
//      case Some(fact) =>
//        val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
//        s.pointsToSet(thisSlot, currentContext).map(v => new RFAFact(fact.s, v))
//      case None =>  isetEmpty
//    }
//
//  }

  private def getPointStringToField(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val newStringIns = PTAPointStringInstance(currentContext)
    thisValue.foreach{
      ins =>
        newfacts += new RFAFact(FieldSlot(ins, "value"), newStringIns)
    }
    newfacts
  }
  
  private def getConcreteStringToField(str: String, s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.nonEmpty)
    var newfacts = isetEmpty[RFAFact]
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val newStringIns = PTAConcreteStringInstance(str, currentContext)
    thisValue.foreach{
      ins =>
        newfacts += new RFAFact(FieldSlot(ins, "value"), newStringIns)
    }
    newfacts
  }
  
  private def getFactFromArgToField(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
    require(args.size > 1)
    var newfacts = isetEmpty[RFAFact]
      val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramValues = s.pointsToSet(paramSlot, currentContext)
    thisValue.foreach{
      ins =>
        newfacts ++= paramValues.map{v => new RFAFact(FieldSlot(ins, "value"), v)}
    }
    newfacts
  }
 
    private def getPointStringToFieldAndThisToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
        require(args.nonEmpty)
      var newfacts = isetEmpty[RFAFact]   
      val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
      val thisValue = s.pointsToSet(thisSlot, currentContext)
      val newStringIns = PTAPointStringInstance(currentContext)
      thisValue.foreach{
        ins =>
          newfacts += new RFAFact(FieldSlot(ins, "value"), newStringIns)
      }
      val facts = getReturnFactsWithAlias(new JawaType("java.lang.StringBuilder"), retVar, currentContext, thisValue)
      newfacts ++= facts
      newfacts
    }
    
    private def getStringBuilderFieldFactToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] ={
      require(args.nonEmpty)
      val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
      val thisValues = s.pointsToSet(thisSlot, currentContext)
      if(thisValues.nonEmpty){
          val strValues = thisValues.map{ins => s.pointsToSet(FieldSlot(ins, "value"), currentContext)}.reduce(iunion[Instance])
          strValues.map(v => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v))
      } else isetEmpty
    }
    
    private def getNewAndOldFieldFact(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) ={
      var newfacts = isetEmpty[RFAFact]
      var deletefacts = isetEmpty[RFAFact]
      require(args.nonEmpty)
      val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
      val thisValue = s.pointsToSet(thisSlot, currentContext)
      thisValue.foreach{
        sbIns => 
          val fieldValue = s.pointsToSet(FieldSlot(sbIns, "value"), currentContext)
          var newFieldValue = isetEmpty[Instance]
          fieldValue.foreach {
            case instance: PTAConcreteStringInstance =>
              val newstr = instance.string.reverse
              val newStringIns = PTAConcreteStringInstance(newstr, currentContext)
              newFieldValue += newStringIns

            case fIns => newFieldValue += fIns
          }
          newfacts ++= newFieldValue.map(v => new RFAFact(FieldSlot(sbIns, "value"), v))
          if(fieldValue.nonEmpty)
            deletefacts ++= fieldValue.map(v => new RFAFact(FieldSlot(sbIns, "value"), v))
        }
      (newfacts  , deletefacts) 
    }
    

     
  def doStringBuilderCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val deleteFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
    case "Ljava/lang/StringBuilder;.<init>:()V" =>
      newFacts ++= getConcreteStringToField("", s, args, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.<init>:(I)V" =>
      newFacts ++= getPointStringToField(s, args, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.<init>:(Ljava/lang/CharSequence;)V" =>
      newFacts ++= getPointStringToField(s, args, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.<init>:(Ljava/lang/String;)V" =>
      newFacts ++= getFactFromArgToField(s, args, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(C)Ljava/lang/Appendable;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(C)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(D)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(F)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(I)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(J)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;)Ljava/lang/Appendable;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;II)Ljava/lang/Appendable;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/Object;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Ljava/lang/StringBuffer;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:(Z)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:([C)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.append:([CII)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.appendCodePoint:(I)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.capacity:()I" =>
    case "Ljava/lang/StringBuilder;.charAt:(I)C" =>
    case "Ljava/lang/StringBuilder;.codePointAt:(I)I" =>
    case "Ljava/lang/StringBuilder;.codePointBefore:(I)I" =>
    case "Ljava/lang/StringBuilder;.codePointCount:(II)I" =>
    case "Ljava/lang/StringBuilder;.delete:(II)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.deleteCharAt:(I)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.ensureCapacity:(I)V" =>
    case "Ljava/lang/StringBuilder;.getChars:(II[CI)V" =>
    case "Ljava/lang/StringBuilder;.indexOf:(Ljava/lang/String;)I" =>
    case "Ljava/lang/StringBuilder;.indexOf:(Ljava/lang/String;I)I" =>
    case "Ljava/lang/StringBuilder;.insert:(IC)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(ID)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(IF)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(II)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(IJ)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(ILjava/lang/CharSequence;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(ILjava/lang/CharSequence;II)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(ILjava/lang/Object;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(ILjava/lang/String;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(IZ)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(I[C)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.insert:(I[CII)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.lastIndexOf:(Ljava/lang/String;)I" =>
    case "Ljava/lang/StringBuilder;.lastIndexOf:(Ljava/lang/String;I)I" =>
    case "Ljava/lang/StringBuilder;.length:()I" =>
    case "Ljava/lang/StringBuilder;.offsetByCodePoints:(II)I" =>
    case "Ljava/lang/StringBuilder;.readObject:(Ljava/io/ObjectInputStream;)V" =>
    case "Ljava/lang/StringBuilder;.replace:(IILjava/lang/String;)Ljava/lang/StringBuilder;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringToFieldAndThisToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    /*TODO*/
    case "Ljava/lang/StringBuilder;.reverse:()Ljava/lang/StringBuilder;" =>
      getNewAndOldFieldFact(s, args, currentContext) match {
        case (newF, oldF) => 
          newFacts ++=newF
          // deleteFacts ++=oldF
      }
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.setCharAt:(IC)V" =>
    case "Ljava/lang/StringBuilder;.setLength:(I)V" =>
    case "Ljava/lang/StringBuilder;.subSequence:(II)Ljava/lang/CharSequence;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringForRet(retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.substring:(I)Ljava/lang/String;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringForRet(retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.substring:(II)Ljava/lang/String;" =>
      require(retVars.size == 1)
      newFacts ++= getPointStringForRet(retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.toString:()Ljava/lang/String;" =>
      require(retVars.size == 1)
      newFacts ++= getStringBuilderFieldFactToRet(s, args, retVars.head, currentContext)
      byPassFlag = false
    case "Ljava/lang/StringBuilder;.trimToSize:()V" =>
    case "Ljava/lang/StringBuilder;.writeObject:(Ljava/io/ObjectOutputStream;)V" =>
    case _ =>
    }
    //val s1 = s -- deleteFacts
    (newFacts, deleteFacts, byPassFlag) 
  }
  
  
}
