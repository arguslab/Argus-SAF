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

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.amandroid.core.security.AndroidProblemCategories
import org.argus.jawa.alir.cfg.ICFGCallNode
import org.argus.jawa.alir.dda.{DataDependenceBaseGraph, IDDGCallArgNode, InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.taintAnalysis._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidDataDependentTaintAnalysis {
  final val TITLE = "AndroidDataDependentTaintAnalysis"

  case class Tp(path: IList[InterProceduralDataDependenceAnalysis.Edge]) extends TaintPath {
    var srcN: TaintSource = _
    var sinN: TaintSink = _
    val typs: MSet[String] = msetEmpty
    def getSource: TaintSource = srcN
    def getSink: TaintSink = sinN
    def getTypes: ISet[String] = this.typs.toSet
    def getPath: IList[TaintNode] = {
      val list: MList[TaintNode] = mlistEmpty
      val rpath = path.reverse
      rpath.headOption match {
        case Some(head) =>
          list += TaintNode(head.target.getICFGNode, head.target.getPosition.map(new SSPosition(_)))
        case None =>
      }
      rpath.foreach { edge =>
        list += TaintNode(edge.source.getICFGNode, edge.source.getPosition.map(new SSPosition(_)))
      }
      list.toList
    }
    override def toString: String = {
      val sb = new StringBuilder
      sb.append("Taint path: ")
      this.typs foreach (typ => sb.append(typ + " "))
      sb.append("\n")
      sb.append(srcN.descriptor + "\n\t-> " + sinN.descriptor + "\n")
      path.reverse.foreach{ edge =>
        sb.append(edge.target + "\n\t-> ")
      }
      sb.append(path.head.source + "\n")
      sb.toString().intern
    }
  }
  
  class TarApk extends TaintAnalysisResult {
    var tars: MSet[TaintAnalysisResult] = msetEmpty
    def getSourceNodes: ISet[TaintSource] = tars.map(_.getSourceNodes).fold(isetEmpty)(_ ++ _)
    def getSinkNodes: ISet[TaintSink] = tars.map(_.getSinkNodes).fold(isetEmpty)(_ ++ _)
    def getTaintedPaths: ISet[TaintPath] = tars.map(_.getTaintedPaths).fold(isetEmpty)(_ ++ _)
  }
  
  case class Tar(iddi: InterProceduralDataDependenceInfo) extends TaintAnalysisResult {
    var sourceNodes: ISet[TaintSource] = isetEmpty
    var sinkNodes: ISet[TaintSink] = isetEmpty
    def getSourceNodes: ISet[TaintSource] = this.sourceNodes
    def getSinkNodes: ISet[TaintSink] = this.sinkNodes
    def getTaintedPaths: ISet[TaintPath] = {
      var tps: ISet[TaintPath] = isetEmpty
      sinkNodes.foreach { sinN =>
        sourceNodes.foreach { srcN =>
          val path = iddi.getDependentPath(iddi.getIddg.getNode(sinN.node.node, sinN.node.pos.map(p => p.pos)), iddi.getIddg.getNode(srcN.node.node, srcN.node.pos.map(p => p.pos)))
          if(path.nonEmpty) {
            val tp = Tp(path)
            tp.srcN = srcN
            tp.sinN = sinN
            val srcTyp = srcN.descriptor.typ
            val sinTyp = sinN.descriptor.typ
            if(srcTyp == SourceAndSinkCategory.API_SOURCE || srcTyp == SourceAndSinkCategory.CALLBACK_SOURCE) {
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.MAL_INFORMATION_LEAK
            } else if(srcTyp == SourceAndSinkCategory.ENTRYPOINT_SOURCE) {
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
            } else if(srcTyp == SourceAndSinkCategory.STMT_SOURCE){
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
            }
            if(tp.typs.nonEmpty) {
              tps += tp
            }
          }
        }
      }
      tps
    }
    
    override def toString: String = {
      val sb = new StringBuilder
      val paths = getTaintedPaths
      if(paths.nonEmpty) {
        getTaintedPaths.foreach(tp => sb.append(tp.toString) + "\n")
      }
      sb.toString.intern()
    }
  }
    
  def apply(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaresult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult
    = build(yard, iddi, ptaresult, ssm)
  
  def build(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaresult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult = {
    val sourceNodes: MSet[TaintSource] = msetEmpty
    val sinkNodes: MSet[TaintSink] = msetEmpty
    val iddg = iddi.getIddg
    iddg.nodes.foreach{ node =>
      yard.getApk(node.getContext.application) match {
        case Some(apk) =>
          val (src, sin) = ssm.getSourceAndSinkNode(apk, node.getICFGNode, node.getPosition, ptaresult)
          sourceNodes ++= src
          sinkNodes ++= sin
        case _ =>
      }
    }
    sinkNodes foreach { sinkNode =>
      sinkNode.node.node match {
        case icfgNode: ICFGCallNode =>
          iddg.getNode(icfgNode, sinkNode.node.pos.map(p => p.pos)) match {
            case iddgNode: IDDGCallArgNode =>
              extendIDDGForSinkApis(iddg, iddgNode, ptaresult)
            case _ =>
          }
        case _ =>
      }
    }
    val tar = Tar(iddi)
    tar.sourceNodes = sourceNodes.toSet
    tar.sinkNodes = sinkNodes.filter { sn =>
      sn.node.node match {
        case cn: ICFGCallNode =>
          var flag = true
          yard.getApk(cn.getContext.application) match {
            case Some(apk) =>
              if(InterComponentCommunicationModel.isIccOperation(cn.getCalleeSig)) {
                flag = ssm.isIntentSink(apk, cn, sn.node.pos.map(p => p.pos), ptaresult)
              }
            case _ =>
          }
          flag
        case _ => true
      }
    }.toSet
    
    val tps = tar.getTaintedPaths
    if(tps.nonEmpty) {
      System.err.println(TITLE + " found " + tps.size + s" path${if(tps.size > 1)"s" else ""}.")
      System.err.println(tar.toString)
    }
    tar
  }
  
  private def extendIDDGForSinkApis(iddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node], callArgNode: IDDGCallArgNode, ptaresult: PTAResult): Unit = {
    val argSlot = VarSlot(callArgNode.argName)
    val argValue = ptaresult.pointsToSet(callArgNode.getContext, argSlot)
    val argRelatedValue = ptaresult.getRelatedHeapInstances(callArgNode.getContext, argValue)
    argRelatedValue.foreach{ ins =>
      if(ins.defSite != callArgNode.getContext) {
        iddg.findDefSite(ins.defSite) match {
          case Some(t) => iddg.addEdge(callArgNode, t)
          case None =>
        }
      }
    }
  }
}