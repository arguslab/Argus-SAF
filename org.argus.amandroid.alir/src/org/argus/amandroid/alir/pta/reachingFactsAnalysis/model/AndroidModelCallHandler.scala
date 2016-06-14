/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.Apk
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.alir.pta.{PTAResult, PTAScopeManager}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCallHandler
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidModelCallHandler extends ModelCallHandler{

  /**
   * return true if the given callee procedure needs to be modeled
   */
  override def isModelCall(calleeMethod: JawaMethod): Boolean = {
    val r = calleeMethod.getDeclaringClass
    BundleModel.isBundle(r) ||
    HandlerModel.isHandler(r) ||
    ComponentNameModel.isComponentName(r) ||
    IntentFilterModel.isIntentFilter(r) ||
    IntentModel.isIntent(r) ||
    UriModel.isUri(r) ||
    FrameworkMethodsModel.isFrameworkMethods(calleeMethod) ||
    ActivityModel.isActivity(r) ||
    super.isModelCall(calleeMethod) ||
    PTAScopeManager.shouldBypass(r)
  }
  
  def isICCCall(calleeSig: Signature): Boolean = {
    InterComponentCommunicationModel.isIccOperation(calleeSig)
  }
  
  /**
   * instead of doing operation inside callee procedure's real code, we do it manually and return the result. 
   */
  override def caculateResult[T](s: PTAResult, calleeMethod: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context, addition: Option[T])(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    val r = calleeMethod.getDeclaringClass
    if(BundleModel.isBundle(r)) BundleModel.doBundleCall(s, calleeMethod, args, retVars, currentContext)
    else if(HandlerModel.isHandler(r)) HandlerModel.doHandlerCall(s, calleeMethod, args, retVars, currentContext)
    else if(ComponentNameModel.isComponentName(r)) ComponentNameModel.doComponentNameCall(s, calleeMethod, args, retVars, currentContext)
    else if(IntentFilterModel.isIntentFilter(r)) IntentFilterModel.doIntentFilterCall(s, calleeMethod, args, retVars, currentContext)
    else if(IntentModel.isIntent(r)) IntentModel.doIntentCall(s, calleeMethod, args, retVars, currentContext)
    else if(UriModel.isUri(r)) UriModel.doUriCall(s, calleeMethod, args, retVars, currentContext)
    else if(FrameworkMethodsModel.isFrameworkMethods(calleeMethod)) FrameworkMethodsModel.doFrameworkMethodsModelCall(calleeMethod.getDeclaringClass.global, addition.get.asInstanceOf[Apk], s, calleeMethod, args, retVars, currentContext)
    else if(ActivityModel.isActivity(r)) ActivityModel.doActivityCall(s, calleeMethod, args, retVars, currentContext)
    else if(super.isModelCall(calleeMethod)) super.caculateResult(s, calleeMethod, args, retVars, currentContext, addition)
    else if(PTAScopeManager.shouldBypass(r)) BypassedModel.handleBypass(s, calleeMethod, args, retVars, currentContext)
    else throw new RuntimeException("given callee is not a model call: " + calleeMethod)
  }

  def doICCCall(global: Global, apk: Apk, s: PTAResult, calleeSig: Signature, args: List[String], retVars: Seq[String], currentContext: Context): (ISet[RFAFact], ISet[JawaMethod]) = {
    if(InterComponentCommunicationModel.isIccOperation(calleeSig)) InterComponentCommunicationModel.doIccCall(global, apk, s, calleeSig, args, retVars, currentContext)
    else throw new RuntimeException("given callee is not an ICC call: " + calleeSig)
  }

}
