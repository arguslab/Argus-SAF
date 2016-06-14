/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
import org.argus.amandroid.core.Apk
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode}
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.core.{Global, Signature}
import org.sireum.util._
import org.sireum.pilar.ast._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentInjectionSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls: Map[Int, LayoutControl], 
    callbackSigs: ISet[Signature], 
    sasFilePath: String) 
    extends AndroidSourceAndSinkManager(global, apk, layoutControls, callbackSigs, sasFilePath){
  
  override def isSource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    false
  }
  
  override def isCallbackSource(sig: Signature): Boolean = {
    false
  }
  
  override def isUISource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
//  if(calleeMethod.getSignature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeMethod.getSignature == AndroidConstants.VIEW_FINDVIEWBYID){
//    val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerMethod, callerLoc, 1)
//    nums.foreach{
//      num =>
//        this.layoutControls.get(num) match{
//          case Some(control) =>
//            return control.isSensitive
//          case None =>
//            err_msg_normal("Layout control with ID " + num + " not found.")
//        }
//    }
//  }
    false
  }

  override def isIccSink(invNode: ICFGInvokeNode, ptaresult: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
//          val rfafactMap = ReachingFactsAnalysisHelper.getFactMap(rfaFact)
//          val args = invNode.getOwner.getMethodBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
//              case te: TupleExp =>
//                te.exps.map{
//            exp =>
//              exp match{
//            case ne: NameExp => ne.name.name
//            case _ => exp.toString()
//          }
//          }.toList
//              case a => throw new RuntimeException("wrong exp type: " + a)
//            }
//          val intentSlot = VarSlot(args(1))
//          val intentValues = rfafactMap.getOrElse(intentSlot, isetEmpty)
//          val intentContents = IntentHelper.getIntentContents(rfafactMap, intentValues, invNode.getContext)
//          val comMap = IntentHelper.mappingIntents(intentContents)
//          comMap.foreach{
//            case (_, coms) =>
//              if(coms.isEmpty) sinkflag = true
//              coms.foreach{
//                case (com, typ) =>
//                  typ match {
//                    case IntentHelper.IntentType.EXPLICIT => if(com.isPhantom) sinkflag = true
////                    case IntentHelper.IntentType.EXPLICIT => sinkflag = true
//                    case IntentHelper.IntentType.IMPLICIT => sinkflag = true
//                  }
//              }
//          }
        }
    }
    sinkflag
  }

  override def isIccSource(entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean = {
    entNode == iddgEntNode
  }
}
