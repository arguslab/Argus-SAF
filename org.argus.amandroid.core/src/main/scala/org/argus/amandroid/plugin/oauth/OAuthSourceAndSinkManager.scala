/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.oauth

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.jawa.alir.controlFlowGraph.{ICFGInvokeNode, ICFGNode}
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.sireum.pilar.ast.{JumpLocation, _}
import org.sireum.util._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class OAuthSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls: Map[Int, LayoutControl], 
    callbackSigs: ISet[Signature], 
    sasFilePath: String) extends AndroidSourceAndSinkManager(global, apk, layoutControls, callbackSigs, sasFilePath){
  
//  private final val TITLE = "OAuthSourceAndSinkManager"
    
  override def isSource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation) = false
    
  override def isCallbackSource(sig: Signature): Boolean = {
    false
  }
  
  override def isUISource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    false
  }

  override def isSource(loc: LocationDecl, ptaresult: PTAResult): Boolean = {
    var flag = false
    val visitor = Visitor.build({
      case as: AssignAction =>
        as.rhs match {
          case le: LiteralExp =>
            if(le.typ.name.equals("STRING")){
              if(le.text.contains("content://call_log/calls"))
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

  def isIccSink(invNode: ICFGInvokeNode, ptaresult: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          sinkflag = true
          val args = global.getMethod(invNode.getOwner).get.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match{
              case te: TupleExp =>
                te.exps.map {
                  case ne: NameExp => ne.name.name
                  case exp => exp.toString
                }.toList
              case a => throw new RuntimeException("wrong exp type: " + a)
          }
          val intentSlot = VarSlot(args(1), isBase = false, isArg = true)
          val intentValues = ptaresult.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(ptaresult, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(global, apk, intentContents, compType)
          comMap.foreach{
            case (_, coms) =>
              if(coms.isEmpty) sinkflag = true
              coms.foreach{
                case (com, typ) =>
                  typ match {
                    case IntentHelper.IntentType.EXPLICIT => 
                      val clazz = global.getClassOrResolve(com)
                      if(clazz.isUnknown) sinkflag = true
//                    case IntentHelper.IntentType.EXPLICIT => sinkflag = true
                    case IntentHelper.IntentType.IMPLICIT => sinkflag = true
                  }
              }
          }
        }
    }
    sinkflag
  }

	def isIccSource(entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean = {
	  false
	}
	
}
