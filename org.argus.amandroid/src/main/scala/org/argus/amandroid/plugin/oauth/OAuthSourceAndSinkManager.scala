/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.oauth

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode}
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.compiler.parser.{AssignmentStatement, CallStatement, LiteralExpression, Location}
import org.argus.jawa.core.util._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class OAuthSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){
  
//  private final val TITLE = "OAuthSourceAndSinkManager"
    
  override def isSource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location) = false

  override def isSource(apk: ApkGlobal, loc: Location, ptaresult: PTAResult): Boolean = {
    var flag = false
    val visitor = Visitor.build({
      case as: AssignmentStatement =>
        as.rhs match {
          case le: LiteralExpression =>
            if(le.isString){
              if(le.getString.contains("content://call_log/calls"))
                flag = true
            }
            false
          case _ =>
            false
        }
    })
  
    visitor(loc)
    flag
  }

  def isIccSink(apk: ApkGlobal, invNode: ICFGInvokeNode, ptaresult: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
          val args = apk.getMethod(invNode.getOwner).get.getBody.resolvedBody.locations(invNode.locIndex).statement.asInstanceOf[CallStatement].args
          val intentSlot = VarSlot(args.head)
          val intentValues = ptaresult.pointsToSet(invNode.getContext, intentSlot)
          val intentContents = IntentHelper.getIntentContents(ptaresult, intentValues, invNode.getContext)
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

	def isIccSource(apk: ApkGlobal, entNode: ICFGNode): Boolean = {
	  false
	}
	
}
