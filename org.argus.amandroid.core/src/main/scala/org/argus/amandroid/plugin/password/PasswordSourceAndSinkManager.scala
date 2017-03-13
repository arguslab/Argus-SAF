/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.password

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode}
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.sireum.pilar.ast.JumpLocation
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class PasswordSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){
  private final val TITLE = "PasswordSourceAndSinkManager"
    
  def isCallbackSource(apk: ApkGlobal, sig: Signature): Boolean = {
    false
  }
  
  def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    if(calleeSig.signature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig.signature == AndroidConstants.VIEW_FINDVIEWBYID){
      val callerMethod = apk.getMethod(callerSig).get
      val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerMethod, callerLoc, 1)
      nums.foreach{
        num =>
          apk.model.getLayoutControls.get(num) match{
            case Some(control) =>
              return control.isSensitive
            case None =>
              apk.reporter.error(TITLE, "Layout control with ID " + num + " not found.")
          }
      }
    }
    false
  }

  def isIccSink(apk: ApkGlobal, invNode: ICFGInvokeNode, ptaResult: PTAResult): Boolean = {
    var sinkFlag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkFlag = true
          val args = PilarAstHelper.getCallArgs(apk.getMethod(invNode.getOwner).get.getBody, invNode.getLocIndex)
          val intentSlot = VarSlot(args(1), isBase = false, isArg = true)
          val intentValues = ptaResult.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(ptaResult, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(apk, intentContents, compType)
          comMap.foreach{
            case (_, coms) =>
              if(coms.isEmpty) sinkFlag = true
              coms.foreach{
                case (com, typ) =>
                  typ match {
                    case IntentHelper.IntentType.EXPLICIT => 
                      val clazz = apk.getClassOrResolve(com)
                      if(clazz.isUnknown) sinkFlag = true
                    case IntentHelper.IntentType.IMPLICIT => sinkFlag = true
                  }
              }
          }
        }
    }
    sinkFlag
  }

  def isIccSource(apk: ApkGlobal, entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean = {
    false
  }

}
