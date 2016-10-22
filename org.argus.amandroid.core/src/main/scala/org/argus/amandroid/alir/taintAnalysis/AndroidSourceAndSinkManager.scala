/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataDependenceAnalysis._
import org.argus.jawa.alir.interprocedural.InterproceduralNode
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.taintAnalysis._
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.core.{Global, Signature}
import org.sireum.util._
import org.sireum.pilar.ast.LocationDecl
import org.sireum.pilar.ast.JumpLocation
import org.sireum.pilar.ast._

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
abstract class AndroidSourceAndSinkManager(
    global: Global,
    apk: Apk,
    layoutControls: Map[Int, LayoutControl], 
    callbackSigs: ISet[Signature], 
    val sasFilePath: String) extends SourceAndSinkManager{
  
  private final val TITLE = "BasicSourceAndSinkManager"
  parse()
  def getSourceAndSinkNode[N <: InterproceduralNode](node: N, ptaresult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    node match {
      case icfgN: ICFGNode => handleICFGNode(icfgN, ptaresult)
      case iddgN: IDDGNode => handleIDFGNode(iddgN, ptaresult)
      case _ => (isetEmpty, isetEmpty)
    }
  }
  
  private def getSourceTags(calleeSig: Signature): ISet[String] = {
    this.sources.filter(src => matchs(calleeSig, src._1)).values.fold(isetEmpty)(iunion)
  }
  
  private def getSinkTags(calleeSig: Signature): ISet[String] = {
    this.sinks.filter(sink => matchs(calleeSig, sink._1)).map(_._2._2).fold(isetEmpty)(iunion)
  }
  
  private def handleICFGNode[N <: InterproceduralNode](icfgN: ICFGNode, ptaresult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    val sources = msetEmpty[TaintSource[N]]
    val sinks = msetEmpty[TaintSink[N]]
    val gNode = icfgN.asInstanceOf[N]
    icfgN match {
      case invNode: ICFGInvokeNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{
          callee =>
            val calleeSig = callee.callee
            val caller = global.getMethod(invNode.getOwner).get
            val jumpLoc = caller.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
            if(this.isSource(calleeSig, invNode.getOwner, jumpLoc)) {
              var tags = getSourceTags(calleeSig)
              if(tags.isEmpty) tags += "ANY"
              global.reporter.echo(TITLE, "found source: " + calleeSig + "@" + invNode.getContext + " " + tags)
              val tn = TaintSource(gNode, TagTaintDescriptor(calleeSig.signature, isetEmpty, SourceAndSinkCategory.API_SOURCE, tags))
              sources += tn
            }
            if(this.isSink(calleeSig)) {
              var tags = getSinkTags(calleeSig)
              if(tags.isEmpty) tags += "ANY"
              global.reporter.echo(TITLE, "found sink: " + calleeSig + "@" + invNode.getContext + " " + tags)
              val poss = this.sinks.filter(sink => matchs(calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
              val tn = TaintSink(gNode, TagTaintDescriptor(calleeSig.signature, poss, SourceAndSinkCategory.API_SINK, tags))
              sinks += tn
            }
            invNode match {
              case invNode1: ICFGCallNode if this.isIccSink(invNode1, ptaresult) =>
                global.reporter.echo(TITLE, "found icc sink: " + invNode)
                val tn = TaintSink(gNode, TagTaintDescriptor(invNode.getLocUri, Set(1), SourceAndSinkCategory.ICC_SINK, Set("ICC")))
                sinks += tn
              case _ =>
            }
        }
      case entNode: ICFGEntryNode =>
        if(this.isIccSource(entNode, entNode)){
          global.reporter.echo(TITLE, "found icc source: " + entNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(entNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.ICC_SOURCE, Set("ICC")))
          sources += tn
        }
        if(this.isCallbackSource(entNode.getOwner)){
          global.reporter.echo(TITLE, "found callback source: " + entNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(entNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.CALLBACK_SOURCE, Set("CALL_BACK")))
          sources += tn
        }
      case normalNode: ICFGNormalNode =>
        val owner = global.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.location(normalNode.getLocIndex)
        if(this.isSource(loc, ptaresult)){
          global.reporter.echo(TITLE, "found simple statement source: " + normalNode)
          val tn = TaintSource(gNode, TagTaintDescriptor(normalNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.STMT_SOURCE, isetEmpty + "ANY"))
          sources += tn
        }
        if(this.isSink(loc, ptaresult)){
          global.reporter.echo(TITLE, "found simple statement sink: " + normalNode)
          val tn = TaintSink(gNode, TagTaintDescriptor(normalNode.getOwner.signature, isetEmpty, SourceAndSinkCategory.STMT_SINK, isetEmpty + "ANY"))
          sinks += tn
        }
      case _ =>
    }
    (sources.toSet, sinks.toSet)
  }
  
  private def handleIDFGNode[N <: InterproceduralNode](iddgN: IDDGNode, ptaresult: PTAResult): (ISet[TaintSource[N]], ISet[TaintSink[N]]) = {
    val sources = msetEmpty[TaintSource[N]]
    val sinks = msetEmpty[TaintSink[N]]
    val gNode = iddgN.asInstanceOf[N]
    iddgN match {
      case invNode: IDDGInvokeNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{
          callee =>
            val calleeSig = callee.callee
            val caller = global.getMethod(invNode.getOwner).get
            val jumpLoc = caller.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation]
            if(invNode.isInstanceOf[IDDGVirtualBodyNode] && this.isSource(calleeSig, invNode.getOwner, jumpLoc)){
              global.reporter.echo(TITLE, "found source: " + calleeSig + "@" + invNode.getContext)
              val tn = TaintSource(gNode, TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
              sources += tn
            }
            invNode match {
              case node: IDDGCallArgNode if this.isSink(calleeSig) =>
                val poss = this.sinks.filter(sink => matchs(calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
                if (poss.isEmpty || poss.contains(node.position)) {
                  global.reporter.echo(TITLE, "found sink: " + calleeSig + "@" + invNode.getContext + " " + node.position)
                  val tn = TaintSink(gNode, TypeTaintDescriptor(calleeSig.signature, Some(node.position), SourceAndSinkCategory.API_SINK))
                  sinks += tn
                }
              case _ =>
            }
            invNode match {
              case node: IDDGCallArgNode if node.position == 1 && this.isIccSink(invNode.getICFGNode.asInstanceOf[ICFGCallNode], ptaresult) =>
                global.reporter.echo(TITLE, "found icc sink: " + invNode)
                val tn = TaintSink(gNode, TypeTaintDescriptor(invNode.getLocUri, Some(1), SourceAndSinkCategory.ICC_SINK))
                sinks += tn
              case _ =>
            }
        }
      case entNode: IDDGEntryParamNode =>
        if(this.isIccSource(entNode.getICFGNode, entNode.getICFGNode)){
          global.reporter.echo(TITLE, "found icc source: " + entNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.ICC_SOURCE))
          sources += tn
        }
        if(entNode.position > 0 && this.isCallbackSource(entNode.getOwner)){
          global.reporter.echo(TITLE, "found callback source: " + entNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.CALLBACK_SOURCE))
          sources += tn
        }
      case normalNode: IDDGNormalNode =>
        val owner = global.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.location(normalNode.getLocIndex)
        if(this.isSource(loc, ptaresult)){
          global.reporter.echo(TITLE, "found simple statement source: " + normalNode)
          val tn = TaintSource(gNode, TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SOURCE))
          sources += tn
        }
        if(this.isSink(loc, ptaresult)){
          global.reporter.echo(TITLE, "found simple statement sink: " + normalNode)
          val tn = TaintSink(gNode, TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SINK))
          sinks += tn
        }
      case _ =>
    }
    (sources.toSet, sinks.toSet)
  }
  
  private def matchs(sig1: Signature, methodpool: ISet[Signature]): Boolean = methodpool.exists{
    sig2 =>
      val clazz1 = global.getClassOrResolve(sig1.classTyp)
      val typ2 = sig2.classTyp
      sig1.getSubSignature == sig2.getSubSignature &&
      (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }
  
  private def matchs(sig1: Signature, sig2: Signature): Boolean = {
    val clazz1 = global.getClassOrResolve(sig1.classTyp)
    val typ2 = sig2.classTyp
      sig1.getSubSignature == sig2.getSubSignature &&
      (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }

  def isSourceMethod(sig: Signature) = matchs(sig, this.sources.keySet.toSet)

  def isSink(sig: Signature) = {
    matchs(sig, this.sinks.keySet.toSet)
  }

  def isSource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    if(isSourceMethod(calleeSig)) return true
    if(isUISource(calleeSig, callerSig, callerLoc)) return true
    false
  }

  def isSource(loc: LocationDecl, ptaresult: PTAResult): Boolean = false

  def isSink(loc: LocationDecl, ptaresult: PTAResult): Boolean = false

  def isCallbackSource(sig: Signature): Boolean
  def isUISource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean
  def isIccSink(invNode: ICFGInvokeNode, s: PTAResult): Boolean
  def isIccSource(entNode: ICFGNode, iddgEntNode: ICFGNode): Boolean

  def getSourceSigs: ISet[Signature] = this.sources.keySet.toSet
  def getSinkSigs: ISet[Signature] = this.sinks.keySet.toSet
  def getInterestedSigs: ISet[Signature] = getSourceSigs ++ getSinkSigs

}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class DefaultAndroidSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls: Map[Int, LayoutControl], 
    callbackSigs: ISet[Signature], 
    sasFilePath: String) extends AndroidSourceAndSinkManager(global, apk, layoutControls, callbackSigs, sasFilePath){

  private final val TITLE = "DefaultSourceAndSinkManager"
  
  def isCallbackSource(sig: Signature): Boolean = {
    if(this.callbackSigs.contains(sig) && sig.getParameterNum > 1) true
    else false
  }

  def isUISource(calleeSig: Signature, callerSig: Signature, callerLoc: JumpLocation): Boolean = {
    if(calleeSig.signature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig.signature == AndroidConstants.VIEW_FINDVIEWBYID){
      val callerProc = global.getMethod(callerSig).get
      val nums = ExplicitValueFinder.findExplicitIntValueForArgs(callerProc, callerLoc, 1)
      nums.foreach{
        num =>
          this.layoutControls.get(num) match{
            case Some(control) =>
              return control.isSensitive
            case None =>
              global.reporter.echo(TITLE, "Layout control with ID " + num + " not found.")
          }
      }
    }
    false
  }

  def isIccSink(invNode: ICFGInvokeNode, s: PTAResult): Boolean = {
    var sinkflag = false
    val calleeSet = invNode.getCalleeSet
    calleeSet.foreach{
      callee =>
        if(InterComponentCommunicationModel.isIccOperation(callee.callee)){
          val args = global.getMethod(invNode.getOwner).get.getBody.location(invNode.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match {
            case te: TupleExp =>
              te.exps.map {
                case ne: NameExp => ne.name.name
                case exp => exp.toString
              }.toList
            case a => throw new RuntimeException("wrong exp type: " + a)
          }
          val intentSlot = VarSlot(args(1), isBase = false, isArg = true)
          val intentValues = s.pointsToSet(intentSlot, invNode.getContext)
          val intentContents = IntentHelper.getIntentContents(s, intentValues, invNode.getContext)
          val compType = AndroidConstants.getIccCallType(callee.callee.getSubSignature)
          val comMap = IntentHelper.mappingIntents(global, apk, intentContents, compType)
          comMap.foreach{
            case (_, comTypes) =>
              if(comTypes.isEmpty) sinkflag = true
              comTypes.foreach{
                case (comType, typ) =>
                  val com = global.getClassOrResolve(comType)
                  typ match {
                    case IntentHelper.IntentType.EXPLICIT => if(com.isUnknown) sinkflag = true
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
    val sourceflag = false
//    val reachableSinks = sinkNodes.filter{sinN => iddg.findPath(entNode, sinN) != null}
//    if(!reachableSinks.isEmpty){
//    val sinkMethods = reachableSinks.filter(_.isInstanceOf[ICFGCallNode]).map(_.asInstanceOf[ICFGCallNode].getCalleeSet).reduce(iunion[Callee])
//    require(!sinkMethods.isEmpty)
//    val neededPermissions = sinkMethods.map(sin => this.apiPermissions.getOrElse(sin.calleeMethod.getSignature, isetEmpty)).reduce(iunion[String])
//    val infos = AppCenter.getAppInfo.getComponentInfos
//    infos.foreach{
//      info =>
//        if(info.name == entNode.getOwner.getDeclaringClass.getName){
//          if(info.exported == true){
//            if(info.permission.isDefined){
//              sourceflag = !(neededPermissions - info.permission.get).isEmpty
//            }
//          }
//        }
//    }
//    }
    sourceflag
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class DataLeakageAndroidSourceAndSinkManager(
    global: Global,
    apk: Apk, 
    layoutControls: Map[Int, LayoutControl], 
    callbackSigs: ISet[Signature], 
    sasFilePath: String) extends DefaultAndroidSourceAndSinkManager(global, apk, layoutControls, callbackSigs, sasFilePath){
  
//  private final val TITLE = "DataLeakageAndroidSourceAndSinkManager"
  
  private def sensitiveData: ISet[String] = Set("android.location.Location", "android.content.Intent")
  
  override def isCallbackSource(sig: Signature): Boolean = {
    if(this.callbackSigs.contains(sig)){
      if(sig.getParameterTypes.exists { pt => sensitiveData.contains(pt.name) }) true
      else false
    }
    else false
  }
}
