/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.dataInjection

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode}
import org.argus.jawa.alir.pta.PTAResult
import org.sireum.pilar.ast._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentInjectionSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){
  
  override def isSource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    false
  }
  
  override def isCallbackSource(apk: ApkGlobal, sig: Signature): Boolean = {
    false
  }
  
  override def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    false
  }

  override def isIccSink(apk: ApkGlobal, invNode: ICFGInvokeNode, ptaResult: PTAResult): Boolean = {
    var sinkFlag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkFlag = true
        }
    }
    sinkFlag
  }

  override def isIccSource(apk: ApkGlobal, entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean = {
    entNode == iddgEntNode
  }
}
