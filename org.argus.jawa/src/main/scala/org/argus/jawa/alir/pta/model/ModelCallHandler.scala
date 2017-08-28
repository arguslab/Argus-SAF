/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.SummaryManager
import org.argus.jawa.summary.susaf.HeapSummaryProcessor

trait ModelCall {
  def safsuFile: String
  def isModelCall(p: JawaMethod): Boolean
  def doModelCall(
      sm: SummaryManager,
      s: ISet[RFAFact],
      p: JawaMethod,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], Boolean) = {
    if(safsuFile == null) return (s, false)
    val summaries = sm.getSummariesByFile(safsuFile)
    summaries.get(p.getSubSignature) match {
      case Some(summary) =>
        (HeapSummaryProcessor.process(p.getDeclaringClass.global, summary, retOpt, recvOpt, args, s, currentContext), true)
      case None =>
        (s, false)
    }
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class ModelCallHandler(scopeManager: ScopeManager) {

  private val modelCalls: MList[ModelCall] = mlistEmpty
  private val callResults: MMap[Signature, Boolean] = mmapEmpty
  private val callModelMap: MMap[Signature, ModelCall] = mmapEmpty
  def registerModelCall(mc: ModelCall): Unit = modelCalls += mc

  registerModelCall(new StringBuilderModel)
  registerModelCall(new StringBufferModel)
  registerModelCall(new StringModel)
  registerModelCall(new ListModel)
  registerModelCall(new SetModel)
  registerModelCall(new MapModel)
  registerModelCall(new ClassModel)
  registerModelCall(new ThreadModel)
  registerModelCall(new ObjectModel)
  registerModelCall(new NativeCallModel)
  registerModelCall(new UnknownCallModel)

  /**
   * return true if the given callee procedure needs to be modeled
   */
  def isModelCall(calleeProc: JawaMethod): Boolean = {
   callResults.get(calleeProc.getSignature) match {
     case Some(r) => r
     case None =>
       val result = modelCalls.exists{ mc =>
         if(mc.isModelCall(calleeProc)) {
           callModelMap(calleeProc.getSignature) = mc
           true
         } else false
       } || scopeManager.shouldBypass(calleeProc.getDeclaringClass)
       callResults(calleeProc.getSignature) = result
       result
    }
  }

  /**
    * Always call isModelCall first.
    */
  def getModelCall(calleeProc: JawaMethod): Option[ModelCall] = {
    callModelMap.get(calleeProc.getSignature)
  }

  /**
    * Always call isModelCall first.
    * instead of doing operation inside callee procedure's real code, we do it manually and return the result.
    */
  def doModelCall(
      sm: SummaryManager,
      s: ISet[RFAFact],
      calleeProc: JawaMethod,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] = {

    callModelMap.get(calleeProc.getSignature) match {
      case Some(model) =>
        var (facts, byPassFlag) = model.doModelCall(sm, s, calleeProc, retOpt, recvOpt, args, currentContext)
        if(!byPassFlag) {
          val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleeProc, s, retOpt, recvOpt, args, currentContext)
          facts ++= newF
          facts --= delF
        }
        return facts
      case None =>
        val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleeProc, s, retOpt, recvOpt, args, currentContext)
        return s ++ newF -- delF
    }
    if(scopeManager.shouldBypass(calleeProc.getDeclaringClass)) {
      val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleeProc, s, retOpt, recvOpt, args, currentContext)
      return s ++ newF -- delF
    }
    throw new RuntimeException("given callee is not a model call: " + calleeProc)
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ObjectModel extends ModelCall {
  def safsuFile: String = "Object.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.Object")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class StringModel extends ModelCall {
  def safsuFile: String = "String.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.String")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class StringBuilderModel extends ModelCall {
  def safsuFile: String = "StringBuilder.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(Constants.STRING_BUILDER)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class StringBufferModel extends ModelCall {
  def safsuFile: String = "StringBuffer.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(Constants.STRING_BUFFER)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class MapModel extends ModelCall {
  def safsuFile: String = "Map.safsu"
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val map = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.MAP))
      p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(map).contains(p.getDeclaringClass)
    }
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SetModel extends ModelCall {
  def safsuFile = "Set.safsu"
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val set = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.SET))
      p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(set).contains(p.getDeclaringClass)
    }
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ListModel extends ModelCall {
  def safsuFile = "List.safsu"
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val list = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.LIST))
      p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(list).contains(p.getDeclaringClass)
    }
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ThreadModel extends ModelCall {
  def safsuFile = "Thread.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.Thread")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class NativeCallModel extends ModelCall {
  def safsuFile = null
  def isModelCall(p: JawaMethod): Boolean = p.isNative
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class UnknownCallModel extends ModelCall {
  def safsuFile = null
  def isModelCall(p: JawaMethod): Boolean = p.isUnknown
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ClassModel extends ModelCall {
  def safsuFile: String = "Class.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.Class")
}