/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.AndroidModelCallHandler
import org.argus.amandroid.core.Apk
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.{Global, JawaMethod, JawaType, Signature}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidReachingFactsAnalysisHelper {

  def isModelCall(calleeMethod: JawaMethod): Boolean = {
    AndroidModelCallHandler.isModelCall(calleeMethod)
  }
  
  def doModelCall(s: PTAResult, calleeMethod: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context, apk: Apk)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    AndroidModelCallHandler.doModelCall(s, calleeMethod, args, retVars, currentContext, Some(apk))
  }
  
  def isICCCall(calleeSig: Signature): Boolean = {
    AndroidModelCallHandler.isICCCall(calleeSig)
  }

  def isRPCCall(apk: Apk, global: Global, currentComp: JawaType, calleeSig: Signature): Boolean = {
    (global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(calleeSig.getClassType, new JawaType("android.os.Messenger"))
      && calleeSig.getSubSignature == "send:(Landroid/os/Message;)V") || apk.getRpcMethodMapping.exists{ case (typ, sigs) => currentComp != typ && sigs.contains(calleeSig)}
  }
  
  def doICCCall(global: Global, apk: Apk, s: PTAResult, calleeSig: Signature, args: List[String], retVars: Seq[String], currentContext: Context): (ISet[RFAFact], ISet[JawaMethod]) = {
    AndroidModelCallHandler.doICCCall(global, apk, s, calleeSig, args, retVars, currentContext)
  }
}
