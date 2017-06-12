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
import org.argus.jawa.core.{JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class StringModel extends ModelCall {
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.String")

//  private def getReturnFactsWithAlias(rType: JawaType, retVar: String, currentContext: Context, alias: ISet[Instance])(implicit factory: RFAFactFactory): ISet[RFAFact] =
//    alias.map{a=> new RFAFact(VarSlot(retVar), a)}

  private def getPointStringForThis(args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val newThisValue = PTAPointStringInstance(currentContext.copy)
    Set(new RFAFact(thisSlot, newThisValue)) 
  }

  private def getFactFromArgForThis(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] = {
    require(args.size > 1)
    val thisSlot = VarSlot(args.head)
    val paramSlot = VarSlot(args(1))
    s.pointsToSet(paramSlot, currentContext).map(v => new RFAFact(thisSlot, v)) 
  }


  private def getOldFactForThis(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    s.pointsToSet(thisSlot, currentContext).map(v => new RFAFact(thisSlot, v))  
  }

  private def getPointStringForRet(retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.String"), retVar, currentContext) match{
      case Some(fact) =>           
        //deleteFacts += fact
        val value = PTAPointStringInstance(currentContext.copy)
        Set(new RFAFact(fact.s, value))
      case None => isetEmpty
    }
   
  }
  
  private def getFactFromThisForRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.nonEmpty)
    ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.String"), retVar, currentContext) match{
      case Some(fact) => 
        val thisSlot = VarSlot(args.head)
        s.pointsToSet(thisSlot, currentContext).map(v => new RFAFact(fact.s, v))
      case None =>  isetEmpty
    }
  }
  
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var deleteFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Ljava/lang/String;.<clinit>:()V" =>
      case "Ljava/lang/String;.<init>:()V" =>
      case "Ljava/lang/String;.<init>:(II[C)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:(Ljava/lang/String;)V" =>
        newFacts ++= getFactFromArgForThis(s, args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:(Ljava/lang/String;C)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:(Ljava/lang/String;I)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      /*TODO: take care of the second string parameter*/
      case "Ljava/lang/String;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      /*TODO: take care of the second and third string parameters*/
      case "Ljava/lang/String;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
        /*TODO:*/
      case "Ljava/lang/String;.<init>:(Ljava/lang/StringBuffer;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
        /*TODO:*/
      case "Ljava/lang/String;.<init>:(Ljava/lang/StringBuilder;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([B)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BI)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BII)V" => 
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BIII)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BIILjava/lang/String;)V" => 
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BIILjava/nio/charset/Charset;)V" =>
         newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BLjava/lang/String;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([BLjava/nio/charset/Charset;)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([C)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([CII)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.<init>:([III)V" =>
        newFacts ++= getPointStringForThis(args, currentContext)
        deleteFacts ++=getOldFactForThis(s, args, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.copyValueOf:([C)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.copyValueOf:([CII)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.failedBoundsCheck:(III)Ljava/lang/StringIndexOutOfBoundsException;" =>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.StringIndexOutOfBoundsException"), retVar, currentContext) match{
          case Some(fact) => 
            newFacts += fact
          case None =>
        }
        byPassFlag = false
      case "Ljava/lang/String;.fastIndexOf:(II)I" =>
      case "Ljava/lang/String;.foldCase:(C)C" =>
      case "Ljava/lang/String;.format:(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.format:(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.indexAndLength:(I)Ljava/lang/StringIndexOutOfBoundsException;" =>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.StringIndexOutOfBoundsException"), retVar, currentContext) match{
          case Some(fact) => 
            newFacts += fact
          case None =>
        }
        byPassFlag = false
      case "Ljava/lang/String;.indexOf:(Ljava/lang/String;Ljava/lang/String;IIC)I" =>
      case "Ljava/lang/String;.indexOfSupplementary:(II)I" =>
      case "Ljava/lang/String;.lastIndexOfSupplementary:(II)I" =>
      case "Ljava/lang/String;.startEndAndLength:(II)Ljava/lang/StringIndexOutOfBoundsException;" =>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("java.lang.StringIndexOutOfBoundsException"), retVar, currentContext) match{
          case Some(fact) => 
            newFacts += fact
          case None =>
        }
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(C)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(D)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(F)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(I)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(J)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;" =>
        require(args.nonEmpty)
        val paramSlot = VarSlot(args.head)
        if(s.pointsToSet(paramSlot, currentContext).nonEmpty){
          var values: ISet[Instance] = isetEmpty
          s.pointsToSet(paramSlot, currentContext).foreach{
            ins=>
              if(ins.isInstanceOf[PTAConcreteStringInstance]) values += ins
              else values += PTAPointStringInstance(currentContext)
          }
          newFacts ++= values.map{v=> new RFAFact(VarSlot(retVar), v)}
        }
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:(Z)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false  
      case "Ljava/lang/String;.valueOf:([C)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.valueOf:([CII)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;._getChars:(II[CI)V" =>
      case "Ljava/lang/String;.charAt:(I)C" =>
      case "Ljava/lang/String;.codePointAt:(I)I" =>
      case "Ljava/lang/String;.codePointBefore:(I)I" =>
      case "Ljava/lang/String;.codePointCount:(II)I" =>
      case "Ljava/lang/String;.compareTo:(Ljava/lang/Object;)I" =>
      case "Ljava/lang/String;.compareTo:(Ljava/lang/String;)I" =>
      case "Ljava/lang/String;.compareToIgnoreCase:(Ljava/lang/String;)I" =>
      case "Ljava/lang/String;.concat:(Ljava/lang/String;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.contains:(Ljava/lang/CharSequence;)Z" =>
      case "Ljava/lang/String;.contentEquals:(Ljava/lang/CharSequence;)Z" =>
      case "Ljava/lang/String;.contentEquals:(Ljava/lang/StringBuffer;)Z" =>
      case "Ljava/lang/String;.endsWith:(Ljava/lang/String;)Z" =>
      case "Ljava/lang/String;.equals:(Ljava/lang/Object;)Z" =>
      case "Ljava/lang/String;.equalsIgnoreCase:(Ljava/lang/String;)Z" =>
      case "Ljava/lang/String;.getBytes:(II[BI)V" =>
      case "Ljava/lang/String;.getBytes:()[B" =>
      case "Ljava/lang/String;.getBytes:(Ljava/lang/String;)[B" =>
      case "Ljava/lang/String;.getBytes:(Ljava/nio/charset/Charset;)[B" =>
      case "Ljava/lang/String;.getChars:(II[CI)V" =>
      case "Ljava/lang/String;.hashCode:()I" =>
      case "Ljava/lang/String;.indexOf:(I)I" =>
      case "Ljava/lang/String;.indexOf:(II)I" =>
      case "Ljava/lang/String;.indexOf:(Ljava/lang/String;)I" =>
      case "Ljava/lang/String;.indexOf:(Ljava/lang/String;I)I" =>
      case "Ljava/lang/String;.intern:()Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.isEmpty:()Z" =>
      case "Ljava/lang/String;.lastIndexOf:(I)I" =>
      case "Ljava/lang/String;.lastIndexOf:(II)I" =>
      case "Ljava/lang/String;.lastIndexOf:(Ljava/lang/String;)I" =>
      case "Ljava/lang/String;.lastIndexOf:(Ljava/lang/String;I)I" =>
      case "Ljava/lang/String;.length:()I" =>
      case "Ljava/lang/String;.matches:(Ljava/lang/String;)Z" =>
      case "Ljava/lang/String;.offsetByCodePoints:(II)I" =>
      case "Ljava/lang/String;.regionMatches:(ILjava/lang/String;II)Z" =>
      case "Ljava/lang/String;.regionMatches:(ZILjava/lang/String;II)Z" =>
      case "Ljava/lang/String;.replace:(CC)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.replace:(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      /*TODO: */
      case "Ljava/lang/String;.replaceAll:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.replaceFirst:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.split:(Ljava/lang/String;)[Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.split:(Ljava/lang/String;I)[Ljava/lang/String;" =>
          newFacts ++= getPointStringForRet(retVar, currentContext)
      case "Ljava/lang/String;.startsWith:(Ljava/lang/String;)Z" =>
      case "Ljava/lang/String;.startsWith:(Ljava/lang/String;I)Z" =>
      case "Ljava/lang/String;.subSequence:(II)Ljava/lang/CharSequence;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.substring:(I)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.substring:(II)Ljava/lang/String;" =>
        newFacts ++= getPointStringForRet(retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.toCharArray:()[C" =>
        /*TODO:*/
      case "Ljava/lang/String;.toLowerCase:()Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.toLowerCase:(Ljava/util/Locale;)Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.toString:()Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
        /*TODO:*/
      case "Ljava/lang/String;.toUpperCase:()Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "Ljava/lang/String;.toUpperCase:(Ljava/util/Locale;)Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
        /*TODO:*/
      case "Ljava/lang/String;.trim:()Ljava/lang/String;" =>
        newFacts ++=getFactFromThisForRet(s, args, retVar, currentContext)
        byPassFlag = false
      case _ =>
    }
    (newFacts, deleteFacts, byPassFlag)
  }
}
