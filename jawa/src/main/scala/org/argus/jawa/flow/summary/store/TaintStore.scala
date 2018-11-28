/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.store

import org.argus.jawa.core.util._
import org.argus.jawa.flow.cfg.ICFGNode
import org.argus.jawa.flow.taintAnalysis._

class TaintStore extends TaintAnalysisResult {
  var sourceNodes: ISet[TaintSource] = isetEmpty
  var sinkNodes: ISet[TaintSink] = isetEmpty

  def getSourceNodes: ISet[TaintSource] = this.sourceNodes
  def getSinkNodes: ISet[TaintSink] = this.sinkNodes

  def getSourceNode(tn: TaintNode): Option[TaintSource] = {
    sourceNodes.find(sn => sn.node == tn)
  }
  def getSinkNode(tn: TaintNode): Option[TaintSink] = {
    sinkNodes.find(sn => sn.node == tn)
  }

  private val paths: MSet[TaintPath] = msetEmpty

  def addTaintPath(path: TaintPath): Unit = this.paths += path
  def addTaintPaths(paths: ISet[TaintPath]): Unit = this.paths ++= paths
  def removeTaintPaths(paths: ISet[TaintPath]): Unit = this.paths --= paths

  def getTaintedPaths: ISet[TaintPath] = {
    paths.toSet
  }

  def merge(ts: TaintStore): TaintStore = {
    sourceNodes ++= ts.sourceNodes
    sinkNodes ++= ts.sinkNodes
    paths ++= ts.getTaintedPaths
    this
  }

  override def toString: String = {
    val sb = new StringBuilder
    val paths = getTaintedPaths
    if(paths.nonEmpty) {
      getTaintedPaths.foreach(tp => sb.append(tp.toString + "\n"))
    }
    sb.toString.intern()
  }
}

case class TSTaintPath(source: TaintSource, sink: TaintSink) extends TaintPath {
  var path: IList[TaintNode] = ilistEmpty

  override def getSource: TaintSource = source

  override def getSink: TaintSink = sink

  override def getTypes: ISet[String] = isetEmpty

  override def getPath: IList[TaintNode] = {
    var prev: ICFGNode = null
    val newPath: MList[TaintNode] = mlistEmpty
    path.foreach { node =>
      if(prev != node.node) {
        newPath += node
      }
      prev = node.node
    }
    newPath.toList
  }

  override def toString: String = {
    val sb = new StringBuilder
    sb.append("Taint path:")
    getTypes foreach (typ => sb.append(typ + " "))
    sb.append("\n")
    sb.append(getSource.descriptor + "\n\t-> " + getSink.descriptor + "\n")
    for(i <- 0 to getPath.size - 2) {
      sb.append(getPath(i) + "\n\t-> ")
    }
    sb.append(getPath.last + "\n")
    sb.toString().trim
  }
}