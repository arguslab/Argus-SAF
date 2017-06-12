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
import org.argus.amandroid.core.security.AndroidProblemCategories
import org.argus.jawa.alir.dataDependenceAnalysis.{DataDependenceBaseGraph, IDDGCallArgNode, InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.taintAnalysis._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidDataDependentTaintAnalysis {
  final val TITLE = "AndroidDataDependentTaintAnalysis"
  type Node = InterProceduralDataDependenceAnalysis.Node
  
  case class Tp(path: IList[InterProceduralDataDependenceAnalysis.Edge]) extends TaintPath[Node, InterProceduralDataDependenceAnalysis.Edge] {
    var srcN: TaintSource[Node] = _
    var sinN: TaintSink[Node] = _
    val typs: MSet[String] = msetEmpty
    def getSource: TaintSource[Node] = srcN
    def getSink: TaintSink[Node] = sinN
    def getTypes: ISet[String] = this.typs.toSet
    def getPath: IList[InterProceduralDataDependenceAnalysis.Edge] = {
      path.reverse.map(edge=> new InterProceduralDataDependenceAnalysis.Edge(edge.owner, edge.target, edge.source))
    }
    def isSame(tp: TaintPath[Node, InterProceduralDataDependenceAnalysis.Edge]): Boolean = getSource.isSame(tp.getSource) && getSink.isSame(tp.getSink)
    def toTaintSimplePath: TaintSimplePath = {
      val source: TaintDescriptor = getSource.descriptor
      val sink: TaintDescriptor = getSink.descriptor
      val path: IList[(TaintSimpleNode, TaintSimpleNode)] = getPath.map {
        edge =>
          val src = edge.source
          val tar = edge.target
          (TaintSimpleNode(src.getContext, src.getPosition), TaintSimpleNode(tar.getContext, tar.getPosition))
      }
      TaintSimplePath(source, sink, path)
    }
    override def toString: String = {
      val sb = new StringBuilder
      sb.append("Taint path: ")
      this.typs foreach (typ => sb.append(typ + " "))
      sb.append("\n")
      sb.append(srcN.descriptor + "\n\t-> " + sinN.descriptor + "\n")
      if(path.size > 1) {
        path.tail.reverse.foreach{
          edge =>
            sb.append(edge.target + "\n\t-> ")
        }
        sb.append(path.head.source + "\n")
      } else if(path.size == 1) {
        sb.append(path.head.target + "\n\t-> ")
        sb.append(path.head.source + "\n")
      }
      sb.toString().intern
    }
  }
  
  class TarApk extends TaintAnalysisResult[Node, InterProceduralDataDependenceAnalysis.Edge] {
    var tars: MSet[TaintAnalysisResult[Node, InterProceduralDataDependenceAnalysis.Edge]] = msetEmpty
    def getSourceNodes: ISet[TaintSource[Node]] = tars.map(_.getSourceNodes).fold(isetEmpty)(_ ++ _)
    def getSinkNodes: ISet[TaintSink[Node]] = tars.map(_.getSinkNodes).fold(isetEmpty)(_ ++ _)
    def getTaintedPaths: ISet[TaintPath[Node, InterProceduralDataDependenceAnalysis.Edge]] = tars.map(_.getTaintedPaths).fold(isetEmpty)(_ ++ _)
    
  }
  
  case class Tar(iddi: InterProceduralDataDependenceInfo) extends TaintAnalysisResult[Node, InterProceduralDataDependenceAnalysis.Edge] {
    var sourceNodes: ISet[TaintSource[Node]] = isetEmpty
    var sinkNodes: ISet[TaintSink[Node]] = isetEmpty
    def getSourceNodes: ISet[TaintSource[Node]] = this.sourceNodes
    def getSinkNodes: ISet[TaintSink[Node]] = this.sinkNodes
    def getTaintedPaths: ISet[TaintPath[Node, InterProceduralDataDependenceAnalysis.Edge]] = {
      var tps: ISet[TaintPath[Node, InterProceduralDataDependenceAnalysis.Edge]] = isetEmpty
      sinkNodes.foreach {
        sinN =>
          sourceNodes.foreach {
            srcN =>
              val path = iddi.getDependentPath(sinN.node, srcN.node)
              if(path.nonEmpty){
                val tp = Tp(path)
                tp.srcN = srcN
                tp.sinN = sinN
                val srcTyp = srcN.descriptor.typ
                val sinTyp = sinN.descriptor.typ
                if(srcTyp == SourceAndSinkCategory.API_SOURCE || srcTyp == SourceAndSinkCategory.CALLBACK_SOURCE){
                  if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.MAL_INFORMATION_LEAK
                  else if(sinTyp == SourceAndSinkCategory.ICC_SINK) tp.typs += AndroidProblemCategories.VUL_INFORMATION_LEAK
                } else if(srcTyp == SourceAndSinkCategory.ICC_SOURCE) {
                  if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
                  else if(sinTyp == SourceAndSinkCategory.ICC_SINK) tp.typs += AndroidProblemCategories.VUL_CONFUSED_DEPUTY
                } else if(srcTyp == SourceAndSinkCategory.STMT_SOURCE){
                  if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
                  else if(sinTyp == SourceAndSinkCategory.ICC_SINK) tp.typs += AndroidProblemCategories.VUL_CONFUSED_DEPUTY
                }
                if(tp.typs.nonEmpty)
                  tps += tp
              }
          }
      }
      tps
    }
    
    override def toString: String = {
      val sb = new StringBuilder
      val paths = getTaintedPaths
      if(paths.nonEmpty){
        getTaintedPaths.foreach(tp => sb.append(tp.toString) + "\n")
      }
      sb.toString.intern()
    }
  }
    
  def apply(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaResult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult[Node, InterProceduralDataDependenceAnalysis.Edge]
    = build(yard, iddi, ptaResult, ssm)
  
  def build(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaResult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult[Node, InterProceduralDataDependenceAnalysis.Edge] = {
    var sourceNodes: ISet[TaintSource[Node]] = isetEmpty
    var sinkNodes: ISet[TaintSink[Node]] = isetEmpty

    val iddg = iddi.getIddg
    iddg.nodes.foreach{ node =>
      yard.getApk(node.getContext.application) match {
        case Some(apk) =>
          val (src, sin) = ssm.getSourceAndSinkNode(apk, node, ptaResult)
          sourceNodes ++= src
          sinkNodes ++= sin
        case _ =>
      }
    }
    sinkNodes foreach {
      sinN =>
        sinN.node match {
          case node: IDDGCallArgNode => extendIDDGForSinkApis(iddg, node, ptaResult)
          case _ =>
        }
    }
    val tar = Tar(iddi)
    tar.sourceNodes = sourceNodes
    tar.sinkNodes = sinkNodes
    
    val tps = tar.getTaintedPaths
    if(tps.nonEmpty){
      System.err.println(TITLE + " found " + tps.size + s" path${if(tps.size > 1)"s" else ""}.")
      System.err.println(tar.toString)
    }
    tar
  }
  
  private def extendIDDGForSinkApis(iddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node], callArgNode: IDDGCallArgNode, ptaresult: PTAResult) = {
    val calleeSet = callArgNode.getCalleeSet
    calleeSet.foreach{ _ =>
      val argSlot = VarSlot(callArgNode.argName)
      val argValue = ptaresult.pointsToSet(argSlot, callArgNode.getContext)
      val argRelatedValue = ptaresult.getRelatedHeapInstances(argValue, callArgNode.getContext)
      argRelatedValue.foreach{
        ins =>
          if(ins.defSite != callArgNode.getContext){
            iddg.findDefSite(ins.defSite) match {
              case Some(t) => iddg.addEdge(callArgNode.asInstanceOf[Node], t)
              case None =>
            }
          }
      }
    }
  }
  
}
