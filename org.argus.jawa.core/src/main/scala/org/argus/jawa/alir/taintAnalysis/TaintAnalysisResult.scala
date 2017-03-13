/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.taintAnalysis

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.interprocedural.InterproceduralNode
import org.sireum.util.ISet
import org.sireum.util.IList
import org.sireum.alir.AlirEdge

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintDescriptor {
  def desc: String
  def typ: String
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TypeTaintDescriptor(desc: String, position: Option[Int], typ: String) extends TaintDescriptor {
  override def toString: String = s"$typ: $desc ${if(position.isDefined) position.get.toString else ""}"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TagTaintDescriptor(desc: String, positions: ISet[Int], typ: String, tags: ISet[String]) extends TaintDescriptor {
  override def toString: String = s"$typ: $desc ${positions.mkString("|")} ${tags.mkString("|")}"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TaintSource[N <: InterproceduralNode](node: N, descriptor: TaintDescriptor) {
  def isSource = true
  def isSink = false
  def isSame(tn: TaintSource[N]): Boolean = descriptor == tn.descriptor && node.getContext.getCurrentLocUri == node.getContext.getCurrentLocUri
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
case class TaintSink[N <: InterproceduralNode](node: N, descriptor: TaintDescriptor) {
  def isSource = false
  def isSink = true
  def isSame(tn: TaintSink[N]): Boolean = descriptor == descriptor && node.getContext.getCurrentLocUri == node.getContext.getCurrentLocUri
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintPath[N <: InterproceduralNode, E <: AlirEdge[N]] {
  def getSource: TaintSource[N]
  def getSink: TaintSink[N]
  def getTypes: ISet[String]
  def getPath: IList[E]
  def isSame(tp: TaintPath[N, E]): Boolean
  def toTaintSimplePath: TaintSimplePath
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait TaintAnalysisResult[N <: InterproceduralNode, E <: AlirEdge[N]] {
  def getSourceNodes: ISet[TaintSource[N]]
  def getSinkNodes: ISet[TaintSink[N]]
  def getTaintedPaths: ISet[TaintPath[N, E]]
  def toTaintAnalysisSimpleResult: TaintAnalysisSimpleResult = {
    val sources: ISet[TaintDescriptor] = getSourceNodes.map(_.descriptor)
    val sinks: ISet[TaintDescriptor] = getSinkNodes.map(_.descriptor)
    val paths: ISet[TaintSimplePath] = getTaintedPaths.map {
      path => path.toTaintSimplePath
    }
    TaintAnalysisSimpleResult(sources, sinks, paths)
  }
}

/**
 * @author <a href="mailto:fwei@mail.usf.edu">Fengguo Wei</a>
 */ 
case class TaintSimpleNode(context: Context, pos: Option[Int])
/**
 * @author <a href="mailto:fwei@mail.usf.edu">Fengguo Wei</a>
 */ 
case class TaintSimplePath(source: TaintDescriptor, sink: TaintDescriptor, path: IList[(TaintSimpleNode, TaintSimpleNode)])
/**
 * @author <a href="mailto:fwei@mail.usf.edu">Fengguo Wei</a>
 */ 
case class TaintAnalysisSimpleResult(sources: ISet[TaintDescriptor], sinks: ISet[TaintDescriptor], paths: ISet[TaintSimplePath])

