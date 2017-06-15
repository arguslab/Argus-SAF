/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCall
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{Constants, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class BundleModel extends ModelCall {
  def isModelCall(r: JawaMethod): Boolean = r.getDeclaringClass.getName.equals(AndroidConstants.BUNDLE)
    
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Landroid/os/Bundle;.<clinit>:()V" =>  //static constructor
      case "Landroid/os/Bundle;.<init>:()V" =>  //public constructor
      case "Landroid/os/Bundle;.<init>:(I)V" =>  //public constructor
      case "Landroid/os/Bundle;.<init>:(Landroid/os/Bundle;)V" =>  //public constructor
        newFacts ++= initBundleFromBundle(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.<init>:(Landroid/os/Parcel;)V" =>  //constructor
      case "Landroid/os/Bundle;.<init>:(Landroid/os/Parcel;I)V" =>  //constructor
      case "Landroid/os/Bundle;.<init>:(Ljava/lang/ClassLoader;)V" =>  //public constructor
      case "Landroid/os/Bundle;.clear:()V" =>  //public
      case "Landroid/os/Bundle;.clone:()Ljava/lang/Object;" =>  //public
        newFacts ++= cloneBundle(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.containsKey:(Ljava/lang/String;)Z" =>  //public
      case "Landroid/os/Bundle;.describeContents:()I" =>  //public
      case "Landroid/os/Bundle;.forPair:(Ljava/lang/String;Ljava/lang/String;)Landroid/os/Bundle;" =>  //public static
        newFacts ++= forPair(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.get:(Ljava/lang/String;)Ljava/lang/Object;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getBoolean:(Ljava/lang/String;)Z" =>  //public
      case "Landroid/os/Bundle;.getBoolean:(Ljava/lang/String;Z)Z" =>  //public
      case "Landroid/os/Bundle;.getBooleanArray:(Ljava/lang/String;)[Z" =>  //public
      case "Landroid/os/Bundle;.getBundle:(Ljava/lang/String;)Landroid/os/Bundle;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getByte:(Ljava/lang/String;)B" =>  //public
      case "Landroid/os/Bundle;.getByte:(Ljava/lang/String;B)Ljava/lang/Byte;" =>  //public
      case "Landroid/os/Bundle;.getByteArray:(Ljava/lang/String;)[B" =>  //public
      case "Landroid/os/Bundle;.getChar:(Ljava/lang/String;)C" =>  //public
      case "Landroid/os/Bundle;.getChar:(Ljava/lang/String;C)C" =>  //public
      case "Landroid/os/Bundle;.getCharArray:(Ljava/lang/String;)[C" =>  //public
      case "Landroid/os/Bundle;.getCharSequence:(Ljava/lang/String;)Ljava/lang/CharSequence;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getCharSequence:(Ljava/lang/String;Ljava/lang/CharSequence;)Ljava/lang/CharSequence;" =>  //public
        newFacts ++= getBundleValueWithDefault(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getCharSequenceArray:(Ljava/lang/String;)[Ljava/lang/CharSequence;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getCharSequenceArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getClassLoader:()Ljava/lang/ClassLoader;" =>  //public
      case "Landroid/os/Bundle;.getDouble:(Ljava/lang/String;)D" =>  //public
      case "Landroid/os/Bundle;.getDouble:(Ljava/lang/String;D)D" =>  //public
      case "Landroid/os/Bundle;.getDoubleArray:(Ljava/lang/String;)[D" =>  //public
      case "Landroid/os/Bundle;.getFloat:(Ljava/lang/String;)F" =>  //public
      case "Landroid/os/Bundle;.getFloat:(Ljava/lang/String;F)F" =>  //public
      case "Landroid/os/Bundle;.getFloatArray:(Ljava/lang/String;)[F" =>  //public
      case "Landroid/os/Bundle;.getIBinder:(Ljava/lang/String;)Landroid/os/IBinder;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getInt:(Ljava/lang/String;)I" =>  //public
      case "Landroid/os/Bundle;.getInt:(Ljava/lang/String;I)I" =>  //public
      case "Landroid/os/Bundle;.getIntArray:(Ljava/lang/String;)[I" =>  //public
      case "Landroid/os/Bundle;.getIntegerArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getLong:(Ljava/lang/String;)J" =>  //public
      case "Landroid/os/Bundle;.getLong:(Ljava/lang/String;J)J" =>  //public
      case "Landroid/os/Bundle;.getLongArray:(Ljava/lang/String;)[J" =>  //public
      case "Landroid/os/Bundle;.getPairValue:()Ljava/lang/String;" =>  //public
      case "Landroid/os/Bundle;.getParcelable:(Ljava/lang/String;)Landroid/os/Parcelable;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getParcelableArray:(Ljava/lang/String;)[Landroid/os/Parcelable;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getParcelableArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getSerializable:(Ljava/lang/String;)Ljava/io/Serializable;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getShort:(Ljava/lang/String;)S" =>  //public
      case "Landroid/os/Bundle;.getShort:(Ljava/lang/String;S)S" =>  //public
      case "Landroid/os/Bundle;.getShortArray:(Ljava/lang/String;)[S" =>  //public
      case "Landroid/os/Bundle;.getSparseParcelableArray:(Ljava/lang/String;)Landroid/util/SparseArray;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getString:(Ljava/lang/String;)Ljava/lang/String;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" =>  //public
        newFacts ++= getBundleValueWithDefault(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getStringArray:(Ljava/lang/String;)[Ljava/lang/String;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.getStringArrayList:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        newFacts ++= getBundleValue(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.hasFileDescriptors:()Z" =>  //public
      case "Landroid/os/Bundle;.isEmpty:()Z" =>  //public
      case "Landroid/os/Bundle;.isParcelled:()Z" =>  //public
      case "Landroid/os/Bundle;.keySet:()Ljava/util/Set;" =>  //public
        newFacts ++= getBundleKeySetToRet(s, args, retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putAll:(Landroid/os/Bundle;)V" =>  //public
        newFacts ++= putAllBundleValues(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putBoolean:(Ljava/lang/String;Z)V" =>  //public
      case "Landroid/os/Bundle;.putBooleanArray:(Ljava/lang/String;[Z)V" =>  //public
      case "Landroid/os/Bundle;.putBundle:(Ljava/lang/String;Landroid/os/Bundle;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putByte:(Ljava/lang/String;B)V" =>  //public
      case "Landroid/os/Bundle;.putByteArray:(Ljava/lang/String;[B)V" =>  //public
      case "Landroid/os/Bundle;.putChar:(Ljava/lang/String;C)V" =>  //public
      case "Landroid/os/Bundle;.putCharArray:(Ljava/lang/String;[C)V" =>  //public
      case "Landroid/os/Bundle;.putCharSequence:(Ljava/lang/String;Ljava/lang/CharSequence;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putCharSequenceArray:(Ljava/lang/String;[Ljava/lang/CharSequence;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putCharSequenceArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putDouble:(Ljava/lang/String;D)V" =>  //public
      case "Landroid/os/Bundle;.putDoubleArray:(Ljava/lang/String;[D)V" =>  //public
      case "Landroid/os/Bundle;.putFloat:(Ljava/lang/String;F)V" =>  //public
      case "Landroid/os/Bundle;.putFloatArray:(Ljava/lang/String;[F)V" =>  //public
      case "Landroid/os/Bundle;.putIBinder:(Ljava/lang/String;Landroid/os/IBinder;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putInt:(Ljava/lang/String;I)V" =>  //public
      case "Landroid/os/Bundle;.putIntArray:(Ljava/lang/String;[I)V" =>  //public
      case "Landroid/os/Bundle;.putIntegerArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putLong:(Ljava/lang/String;J)V" =>  //public
      case "Landroid/os/Bundle;.putLongArray:(Ljava/lang/String;[J)V" =>  //public
      case "Landroid/os/Bundle;.putParcelable:(Ljava/lang/String;Landroid/os/Parcelable;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putParcelableArray:(Ljava/lang/String;[Landroid/os/Parcelable;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putParcelableArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putSerializable:(Ljava/lang/String;Ljava/io/Serializable;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putShort:(Ljava/lang/String;S)V" =>  //public
      case "Landroid/os/Bundle;.putShortArray:(Ljava/lang/String;[S)V" =>  //public
      case "Landroid/os/Bundle;.putSparseParcelableArray:(Ljava/lang/String;Landroid/util/SparseArray;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putString:(Ljava/lang/String;Ljava/lang/String;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putStringArray:(Ljava/lang/String;[Ljava/lang/String;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.putStringArrayList:(Ljava/lang/String;Ljava/util/ArrayList;)V" =>  //public
        newFacts ++= putBundleValue(s, args, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.readFromParcel:(Landroid/os/Parcel;)V" =>  //public
      case "Landroid/os/Bundle;.readFromParcelInner:(Landroid/os/Parcel;I)V" =>  //
      case "Landroid/os/Bundle;.remove:(Ljava/lang/String;)V" =>  //public
      case "Landroid/os/Bundle;.setAllowFds:(Z)Z" =>  //public
      case "Landroid/os/Bundle;.setClassLoader:(Ljava/lang/ClassLoader;)V" =>  //public
      case "Landroid/os/Bundle;.size:()I" =>  //public
      case "Landroid/os/Bundle;.toString:()Ljava/lang/String;" =>  //public declared_synchronized
        newFacts += getPointStringToRet(retVar, currentContext)
        byPassFlag = false
      case "Landroid/os/Bundle;.typeWarning:(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/ClassCastException;)V" =>  //private
      case "Landroid/os/Bundle;.typeWarning:(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/ClassCastException;)V" =>  //private
      case "Landroid/os/Bundle;.unparcel:()V" =>  //declared_synchronized
      case "Landroid/os/Bundle;.writeToParcel:(Landroid/os/Parcel;I)V" =>  //public
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  private def getPointStringToRet(retVar: String, currentContext: Context)(implicit factory: SimHeap): RFAFact = {
    val newThisValue = PTAPointStringInstance(currentContext.copy)
    new RFAFact(VarSlot(retVar), newThisValue)
  }
    
  private def initBundleFromBundle(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.size >1)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val paramSlot = VarSlot(args(1))
    val paramValue = s.pointsToSet(after = false, currentContext, paramSlot)
    if(paramValue.nonEmpty && thisValue.nonEmpty){
      val pvs = paramValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES))}.reduce(iunion[Instance])
      thisValue.map{
        tv =>
          pvs.map{s => new RFAFact(FieldSlot(tv, AndroidConstants.BUNDLE_ENTRIES), s)}
      }.reduce(iunion[RFAFact])
    } else {
      isetEmpty
    }
  }
  
  private def cloneBundle(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    thisValue.map{s => new RFAFact(VarSlot(retVar), s.clone(currentContext))}
  }
  
  private def forPair(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.os.Bundle"), retVar, currentContext).get
    require(args.size >1)
    val param1Slot = VarSlot(args.head)
    val param1Value = s.pointsToSet(after = false, currentContext, param1Slot)
    val param2Slot = VarSlot(args(1))
    val param2Value = s.pointsToSet(after = false, currentContext, param2Slot)
    var entries = isetEmpty[Instance]
    param1Value.foreach{ kv =>
      param2Value.foreach{ vv =>
        entries += PTATupleInstance(kv, vv, currentContext)
      }
    }
    entries.map{s => new RFAFact(FieldSlot(rf.v, AndroidConstants.BUNDLE_ENTRIES), s)}
  }
  
  private def getBundleKeySetToRet(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    if(thisValue.nonEmpty){
      val strValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES))}.reduce(iunion[Instance])
      val rf = ReachingFactsAnalysisHelper.getReturnFact(new JawaType(Constants.HASHSET), retVar, currentContext).get
      result += rf
      result ++= strValue.map{ s =>
        require(s.isInstanceOf[PTATupleInstance])
        new RFAFact(FieldSlot(rf.v, Constants.HASHSET_ITEMS), s.asInstanceOf[PTATupleInstance].left)
      }
    }
    result
  }
  
  private def getBundleValue(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val keySlot = VarSlot(args(1))
    val keyValue = s.pointsToSet(after = false, currentContext, keySlot)
    if(thisValue.nonEmpty){
      val entValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES))}.reduce(iunion[Instance])
      if(!keyValue.exists(_.isInstanceOf[PTAPointStringInstance])){
        entValue.foreach{ v =>
          require(v.isInstanceOf[PTATupleInstance])
          if(keyValue.exists { kIns => kIns === v.asInstanceOf[PTATupleInstance].left }){
            result += new RFAFact(VarSlot(retVar), v.asInstanceOf[PTATupleInstance].right)
          }
        }
      } else {
        entValue.foreach{ v =>
          require(v.isInstanceOf[PTATupleInstance])
          result += new RFAFact(VarSlot(retVar), v.asInstanceOf[PTATupleInstance].right)
        }
      }
    }
    result
  }
  
  private def getBundleValueWithDefault(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >2)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val keySlot = VarSlot(args(1))
    val keyValue = s.pointsToSet(after = false, currentContext, keySlot)
    val defaultSlot = VarSlot(args(2))
    val defaultValue = s.pointsToSet(after = false, currentContext, defaultSlot)
    if(thisValue.nonEmpty){
        val entValue = thisValue.map{ins => s.pointsToSet(after = false, currentContext, FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES))}.reduce(iunion[Instance])
        if(!keyValue.exists(_.isInstanceOf[PTAPointStringInstance])){
          entValue.foreach{
            v =>
              require(v.isInstanceOf[PTATupleInstance])
              if(keyValue.exists { kIns => kIns === v.asInstanceOf[PTATupleInstance].left }){
                result += new RFAFact(VarSlot(retVar), v.asInstanceOf[PTATupleInstance].right)
              }
          }
        } else {
          entValue.foreach{
            v =>
              require(v.isInstanceOf[PTATupleInstance])
              result += new RFAFact(VarSlot(retVar), v.asInstanceOf[PTATupleInstance].right)
          }
        }
    }
    if(result.isEmpty){
      result ++= defaultValue.map(new RFAFact(VarSlot(retVar), _))
    }
    result
  }
  
  private def putBundleValue(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >2)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val keySlot = VarSlot(args(1))
    val keyValue = s.pointsToSet(after = false, currentContext, keySlot)
    val valueSlot = VarSlot(args(2))
    val valueValue = s.pointsToSet(after = false, currentContext, valueSlot)
    var entries = isetEmpty[Instance]
    keyValue.foreach{
      kv =>
        valueValue.foreach{
          vv =>
            thisValue.foreach{
              ins =>
                entries += PTATupleInstance(kv, vv, ins.defSite)
            }
        }
    }
    thisValue.foreach{
      ins =>
        result ++= entries.map(e => new RFAFact(FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES), e))
    }
    result
  }
  
  
  
  private def putAllBundleValues(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] ={
    var result = isetEmpty[RFAFact]
    require(args.size >1)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    val slot2 = VarSlot(args(1))
    val value2 = s.pointsToSet(after = false, currentContext, slot2)
    thisValue.foreach{
      ins =>
        value2.foreach{
          e => 
            val ents = s.pointsToSet(after = false, currentContext, FieldSlot(e, AndroidConstants.BUNDLE_ENTRIES))
            result ++= ents.map(e => new RFAFact(FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES), e))
        }
    }
    result
  }
}
