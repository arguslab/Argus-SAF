/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.taintAnalysis

import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.core.ast.{CallStatement, Location}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.pta.{PTAResult, VarSlot}
import org.argus.jawa.flow.taintAnalysis._
import org.argus.jawa.flow.util.ExplicitValueFinder

object IntentSinkKind extends Enumeration {
  val NO, IMPLICIT, ALL = Value
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class AndroidSourceAndSinkManager(val sasFilePath: String) extends SourceAndSinkManager[ApkGlobal]{

  parse()

  override def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = false

  def getSourceSigs: ISet[Signature] = this.sources.keySet.toSet
  def getSinkSigs: ISet[Signature] = this.sinks.keySet.toSet
  def getInterestedSigs: ISet[Signature] = getSourceSigs ++ getSinkSigs

  override def isSourceMethod(global: ApkGlobal, sig: Signature): Option[(String, ISet[SSPosition])] = {
    if(sig.classTyp.jawaName == AndroidConstants.INTENT && sig.methodName.startsWith("get") && sig.methodName.contains("Extra")) {
      Some((SourceAndSinkCategory.ICC_SOURCE, isetEmpty))
    } else {
      super.isSourceMethod(global, sig)
    }
  }

  override def isSinkMethod(global: ApkGlobal, sig: Signature): Option[(String, ISet[SSPosition])] = {
    if(InterComponentCommunicationModel.isIccOperation(sig)) {
      Some(SourceAndSinkCategory.ICC_SINK, Set(new SSPosition(1)))
    } else {
      super.isSinkMethod(global, sig)
    }
  }

  def intentSink: IntentSinkKind.Value = IntentSinkKind.IMPLICIT

  def isIntentSink(apk: ApkGlobal, invNode: ICFGCallNode, pos: Option[Int], s: PTAResult): Boolean = {
    var sinkflag = false
    if(pos.isEmpty || pos.get !=1) return sinkflag
    intentSink match {
      case IntentSinkKind.NO =>
      case IntentSinkKind.ALL =>
        sinkflag = InterComponentCommunicationModel.isIccOperation(invNode.getCalleeSig)
      case IntentSinkKind.IMPLICIT =>
        if(InterComponentCommunicationModel.isIccOperation(invNode.getCalleeSig)) {
          val args = invNode.argNames
          val intentSlot = VarSlot(args.head)
          val intentValues = s.pointsToSet(invNode.getContext, intentSlot)
          val intentContents = IntentHelper.getIntentContents(s, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(invNode.getCalleeSig.getSubSignature)
          val comMap = IntentHelper.mappingIntents(apk, intentContents, compType)
          comMap.foreach{ case (intent, comTypes) =>
            if(comTypes.isEmpty) sinkflag = true
            comTypes.foreach{ comType =>
              val com = apk.getClassOrResolve(comType)
              if(intent.explicit) {
                if(com.isUnknown) sinkflag = true
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

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class DefaultAndroidSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){

  private final val TITLE = "DefaultSourceAndSinkManager"

  override def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = {
    if(calleeSig.signature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig.signature == AndroidConstants.VIEW_FINDVIEWBYID){
      val callerProc = apk.getMethod(callerSig).get
      val cs = callerLoc.statement.asInstanceOf[CallStatement]
      val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
      nums.filter(_.isInt).foreach{ num =>
        apk.model.getLayoutControls.get(num.getInt) match{
          case Some(control) =>
            return control.isSensitive
          case None =>
            apk.reporter.echo(TITLE, "Layout control with ID " + num + " not found.")
        }
      }
    }
    false
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class DataLeakageAndroidSourceAndSinkManager(sasFilePath: String) extends DefaultAndroidSourceAndSinkManager(sasFilePath){

  private def sensitiveData: ISet[String] = Set("android.location.Location", "android.content.Intent")
  
  override def isCallbackSource(apk: ApkGlobal, sig: Signature, pos: Int): Boolean = {
    apk.model.getComponentInfos foreach { info =>
      if(info.compType == sig.getClassType && !info.exported) return false
    }
    if(apk.model.getCallbackMethods.contains(sig)){
      sig.getParameterTypes.isDefinedAt(pos) && sensitiveData.contains(sig.getParameterTypes(pos).name)
    } else false
  }
}
