/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.taintAnalysis

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.InterProceduralNode
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataDependenceAnalysis._
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.taintAnalysis._
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.compiler.parser.{CallStatement, Location}
import org.argus.jawa.core.Signature
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object SourceAndSinkCategory {
  final val STMT_SOURCE = "stmt_source"
  final val STMT_SINK = "stmt_sink"
  final val API_SOURCE = "api_source"
  final val API_SINK = "api_sink"
  final val ICC_SOURCE = "icc_source"
  final val ICC_SINK = "icc_sink"
  final val CALLBACK_SOURCE = "callback_source"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class AndroidSourceAndSinkManager(val sasFilePath: String) extends SourceAndSinkManager[ApkGlobal]{
  
  private final val TITLE = "AndroidSourceAndSinkManager"
  parse()

  def getSourceAndSinkNode[N <: InterProceduralNode](apk: ApkGlobal, node: N, ptaResult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    node match {
      case icfgN: ICFGNode => handleICFGNode(apk, icfgN, ptaResult)
      case iddgN: IDDGNode => handleIDDGNode(apk, iddgN, ptaResult)
      case _ => (isetEmpty, isetEmpty)
    }
  }
  
  private def getSourceTags(apk: ApkGlobal, calleeSig: Signature): ISet[String] = {
    this.sources.filter(src => matches(apk, calleeSig, src._1)).values.fold(isetEmpty)(iunion)
  }
  
  private def getSinkTags(apk: ApkGlobal, calleeSig: Signature): ISet[String] = {
    this.sinks.filter(sink => matches(apk, calleeSig, sink._1)).map(_._2._2).fold(isetEmpty)(iunion)
  }
  
  private def handleICFGNode[N <: InterProceduralNode](apk: ApkGlobal, icfgN: ICFGNode, ptaResult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    val sources = msetEmpty[TaintSource[N]]
    val sinks = msetEmpty[TaintSink[N]]
    val gNode = icfgN.asInstanceOf[N]
    icfgN match {
      case invNode: ICFGInvokeNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{ callee =>
          val calleeSig = callee.callee
          apk.getMethod(invNode.getOwner) match {
            case Some(caller) =>
              val jumpLoc = caller.getBody.resolvedBody.locations(invNode.locIndex)
              if(this.isSource(apk, calleeSig, invNode.getOwner, jumpLoc)) {
                var tags = getSourceTags(apk, calleeSig)
                if(tags.isEmpty) tags += "ANY"
                apk.reporter.echo(TITLE, "found source: " + calleeSig + "@" + invNode.getContext + " " + tags)
                val tn = TaintSource(gNode, TagTaintDescriptor(calleeSig.signature, isetEmpty, SourceAndSinkCategory.API_SOURCE, tags))
                sources += tn
              }
            case None =>
          }

          if(this.isSink(apk, calleeSig)) {
            var tags = getSinkTags(apk, calleeSig)
            if(tags.isEmpty) tags += "ANY"
            apk.reporter.echo(TITLE, "found sink: " + calleeSig + "@" + invNode.getContext + " " + tags)
            val poss = this.sinks.filter(sink => matches(apk, calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
            val tn = TaintSink(gNode, TagTaintDescriptor(calleeSig.signature, poss, SourceAndSinkCategory.API_SINK, tags))
            sinks += tn
          }
          invNode match {
            case invNode1: ICFGCallNode if this.isIccSink(apk, invNode1, ptaResult) =>
              apk.reporter.echo(TITLE, "found icc sink: " + invNode)
              val tn = TaintSink(gNode, TagTaintDescriptor(invNode.locUri, Set(1), SourceAndSinkCategory.ICC_SINK, Set("ICC")))
              sinks += tn
            case _ =>
          }
        }
      case entNode: ICFGEntryNode =>
        if(this.isIccSource(apk, entNode)){
          apk.reporter.echo(TITLE, "found icc source: " + entNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(entNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.ICC_SOURCE, Set("ICC")))
          sources += tn
        }
        if(this.isCallbackSource(apk, entNode.getOwner, 0)){
          apk.reporter.echo(TITLE, "found callback source: " + entNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(entNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.CALLBACK_SOURCE, Set("CALL_BACK")))
          sources += tn
        }
      case normalNode: ICFGNormalNode =>
        val owner = apk.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.resolvedBody.locations(normalNode.locIndex)
        if(this.isSource(apk, loc, ptaResult)){
          apk.reporter.echo(TITLE, "found simple statement source: " + normalNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(normalNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.STMT_SOURCE, isetEmpty + "ANY"))
          sources += tn
        }
        if(this.isSink(apk, loc, ptaResult)){
          apk.reporter.echo(TITLE, "found simple statement sink: " + normalNode)
          val tn = TaintSink(gNode, TagTaintDescriptor(normalNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.STMT_SINK, isetEmpty + "ANY"))
          sinks += tn
        }
      case _ =>
    }
    (sources.toSet, sinks.toSet)
  }
  
  private def handleIDDGNode[N <: InterProceduralNode](apk: ApkGlobal, iddgN: IDDGNode, ptaresult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    val sources = msetEmpty[TaintSource[N]]
    val sinks = msetEmpty[TaintSink[N]]
    val gNode = iddgN.asInstanceOf[N]
    iddgN match {
      case invNode: IDDGInvokeNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{ callee =>
          val calleeSig = callee.callee
          apk.getMethod(invNode.getOwner) match {
            case Some(caller) =>
              val jumpLoc = caller.getBody.resolvedBody.locations(invNode.getLocIndex)
              if(invNode.isInstanceOf[IDDGVirtualBodyNode] && this.isSource(apk, calleeSig, invNode.getOwner, jumpLoc)){
                apk.reporter.echo(TITLE, "found source: " + calleeSig + "@" + invNode.getContext)
                val tn = TaintSource(gNode, TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
                sources += tn
              }
            case None =>
          }
          invNode match {
            case node: IDDGCallArgNode if this.isSink(apk, calleeSig) =>
              val poss = this.sinks.filter(sink => matches(apk, calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
              if (poss.isEmpty || poss.contains(node.position)) {
                apk.reporter.echo(TITLE, "found sink: " + calleeSig + "@" + invNode.getContext + " " + node.position)
                val tn = TaintSink(gNode, TypeTaintDescriptor(calleeSig.signature, Some(node.position), SourceAndSinkCategory.API_SINK))
                sinks += tn
              }
            case _ =>
          }
          invNode match {
            case node: IDDGCallArgNode if node.position == 1 && this.isIccSink(apk, invNode.getICFGNode.asInstanceOf[ICFGCallNode], ptaresult) =>
              apk.reporter.echo(TITLE, "found icc sink: " + invNode)
              val tn = TaintSink(gNode, TypeTaintDescriptor(invNode.getLocUri, Some(1), SourceAndSinkCategory.ICC_SINK))
              sinks += tn
            case _ =>
          }
        }
      case entNode: IDDGEntryParamNode =>
        if(this.isIccSource(apk, entNode.getICFGNode)){
          apk.reporter.echo(TITLE, "found icc source: " + entNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.ICC_SOURCE))
          sources += tn
        }
        if(entNode.position > 0 && this.isCallbackSource(apk, entNode.getOwner, entNode.position - 1)){
          apk.reporter.echo(TITLE, "found callback source: " + entNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.CALLBACK_SOURCE))
          sources += tn
        }
      case normalNode: IDDGNormalNode =>
        val owner = apk.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.resolvedBody.locations(normalNode.getLocIndex)
        if(this.isSource(apk, loc, ptaresult)){
          apk.reporter.echo(TITLE, "found simple statement source: " + normalNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SOURCE))
          sources += tn
        }
        if(this.isSink(apk, loc, ptaresult)){
          apk.reporter.echo(TITLE, "found simple statement sink: " + normalNode)
          val tn = TaintSink(gNode, TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SINK))
          sinks += tn
        }
      case _ =>
    }
    (sources.toSet, sinks.toSet)
  }
  
  private def matches(apk: ApkGlobal, sig1: Signature, methodPool: ISet[Signature]): Boolean = methodPool.exists{
    sig2 =>
      val clazz1 = apk.getClassOrResolve(sig1.classTyp)
      val typ2 = sig2.classTyp
      sig1.getSubSignature == sig2.getSubSignature &&
      (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }
  
  private def matches(apk: ApkGlobal, sig1: Signature, sig2: Signature): Boolean = {
    val clazz1 = apk.getClassOrResolve(sig1.classTyp)
    val typ2 = sig2.classTyp
      sig1.getSubSignature == sig2.getSubSignature &&
      (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }

  def isSourceMethod(apk: ApkGlobal, sig: Signature): Boolean = matches(apk, sig, this.sources.keySet.toSet)

  def isSink(apk: ApkGlobal, sig: Signature): Boolean = {
    matches(apk, sig, this.sinks.keySet.toSet)
  }

  def isSource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = {
    isSourceMethod(apk, calleeSig) ||
    isUISource(apk, calleeSig, callerSig, callerLoc)
  }

  def isSource(apk: ApkGlobal, loc: Location, ptaResult: PTAResult): Boolean = false

  def isSink(apk: ApkGlobal, loc: Location, ptaResult: PTAResult): Boolean = false

  def isCallbackSource(apk: ApkGlobal, sig: Signature, pos: Int): Boolean = false
  def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = false
  def isIccSink(apk: ApkGlobal, invNode: ICFGInvokeNode, s: PTAResult): Boolean
  def isIccSource(apk: ApkGlobal, entNode: ICFGNode): Boolean

  def getSourceSigs: ISet[Signature] = this.sources.keySet.toSet
  def getSinkSigs: ISet[Signature] = this.sinks.keySet.toSet
  def getInterestedSigs: ISet[Signature] = getSourceSigs ++ getSinkSigs

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
      nums.filter(_.isInt).foreach{
        num =>
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

  def isIccSink(apk: ApkGlobal, invNode: ICFGInvokeNode, s: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          val args = invNode.argNames
          val intentSlot = VarSlot(args(1))
          val intentValues = s.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(s, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(apk, intentContents, compType)
          comMap.foreach{
            case (_, comTypes) =>
              if(comTypes.isEmpty) sinkflag = true
              comTypes.foreach{
                case (comType, typ) =>
                  val com = apk.getClassOrResolve(comType)
                  typ match {
                    case IntentHelper.IntentType.EXPLICIT => if(com.isUnknown) sinkflag = true
                    case IntentHelper.IntentType.IMPLICIT => sinkflag = true
                  }
              }
          }
        }
    }
    sinkflag
  }
  
  def isIccSource(apk: ApkGlobal, entNode: ICFGNode): Boolean = false
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class DataLeakageAndroidSourceAndSinkManager(sasFilePath: String) extends DefaultAndroidSourceAndSinkManager(sasFilePath){

  private def sensitiveData: ISet[String] = Set("android.location.Location", "android.content.Intent")
  
  override def isCallbackSource(apk: ApkGlobal, sig: Signature, pos: Int): Boolean = {
    apk.model.getComponentInfos foreach {
      info =>
        if(info.compType == sig.getClassType && !info.exported) return false
    }
    if(apk.model.getCallbackMethods.contains(sig)){
      sig.getParameterTypes.isDefinedAt(pos) && sensitiveData.contains(sig.getParameterTypes(pos).name)
    } else false
  }
}
