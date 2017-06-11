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
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{JawaMethod, ScopeManager}
import org.argus.jawa.core.util._

trait ModelCall {
  def isModelCall(p: JawaMethod): Boolean
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean)
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class ModelCallHandler(scopeManager: ScopeManager) {

  private val modelCalls: MList[ModelCall] = mlistEmpty
  def registerModelCall(mc: ModelCall): Unit = modelCalls += mc

  registerModelCall(new StringBuilderModel)
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
  def isModelCall(calleeProc: JawaMethod): Boolean = modelCalls.exists(_.isModelCall(calleeProc)) || scopeManager.shouldBypass(calleeProc.getDeclaringClass)
      
  /**
   * instead of doing operation inside callee procedure's real code, we do it manually and return the result. 
   */
  def doModelCall(
      s: PTAResult,
      calleeProc: JawaMethod, 
      args: List[String],
      retVar: Option[String],
      currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact]) = {
    val hackVar = retVar.getOrElse("hack")
    
    modelCalls.foreach{ model =>
      if(model.isModelCall(calleeProc)) {
        var (newFacts, delFacts, byPassFlag) = model.doModelCall(s, calleeProc, args, hackVar, currentContext)
        if(byPassFlag){
          val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleeProc, s, args, hackVar, currentContext)
          newFacts ++= newF
          delFacts ++= delF
        }
        return (newFacts, delFacts)
      }
    }
    if(scopeManager.shouldBypass(calleeProc.getDeclaringClass)) {
      val (newF, delF) = ReachingFactsAnalysisHelper.getUnknownObject(calleeProc, s, args, hackVar, currentContext)
      return (newF, delF)
    }
    throw new RuntimeException("given callee is not a model call: " + calleeProc)
  }
}