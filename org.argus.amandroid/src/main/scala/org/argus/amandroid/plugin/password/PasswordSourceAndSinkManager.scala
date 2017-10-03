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
import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.controlFlowGraph.ICFGInvokeNode
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.ast.{CallStatement, Location}
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class PasswordSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){
  private final val TITLE = "PasswordSourceAndSinkManager"
  
  override def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = {
    if(calleeSig.signature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig.signature == AndroidConstants.VIEW_FINDVIEWBYID){
      val callerMethod = apk.getMethod(callerSig).get
      val cs = callerLoc.statement.asInstanceOf[CallStatement]
      val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerMethod, callerLoc, cs.arg(0))
      nums.filter(_.isInt).foreach{ num =>
        apk.model.getLayoutControls.get(num.getInt) match{
          case Some(control) =>
            return control.isSensitive
          case None =>
            apk.reporter.error(TITLE, "Layout control with ID " + num + " not found.")
        }
      }
    }
    false
  }

  override def isConditionalSink(apk: ApkGlobal, invNode: ICFGInvokeNode, pos: Option[Int], ptaResult: PTAResult): Boolean = {
    var sinkflag = false
    if(pos.isEmpty || pos.get !=1) return sinkflag
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{ callee =>
      if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
        sinkflag = true
        val args = invNode.argNames
        val intentSlot = VarSlot(args(1))
        val intentValues = ptaResult.pointsToSet(invNode.getContext, intentSlot)
        val intentContents = IntentHelper.getIntentContents(ptaResult, intentValues, invNode.getContext)
        val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
        val comMap = IntentHelper.mappingIntents(apk, intentContents, compType)
        comMap.foreach{ case (intent, coms) =>
          if(coms.isEmpty) sinkflag = true
          coms.foreach{ com =>
            if(intent.explicit) {
              val clazz = apk.getClassOrResolve(com)
              if(clazz.isUnknown) sinkflag = true
            } else {
              sinkflag = true
            }
          }
        }
      }
    }
    sinkflag
  }

}
