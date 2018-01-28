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

import org.argus.jawa.core.util._
import java.io.BufferedReader
import java.io.FileReader
import java.util.regex.Pattern
import java.util.regex.Matcher

import org.argus.jawa.alir.cfg._
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.ast.Location
import org.argus.jawa.core.{Global, Signature}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
object SourceAndSinkCategory {
  final val STMT_SOURCE = "stmt_source"
  final val STMT_SINK = "stmt_sink"
  final val API_SOURCE = "api_source"
  final val API_SINK = "api_sink"
  final val ENTRYPOINT_SOURCE = "entrypoint_source"
  final val CALLBACK_SOURCE = "callback_source"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait SourceAndSinkManager[T <: Global] {
  def sasFilePath: String
  /**
   * it's a map from source API sig to it's category
   */
  protected val sources: MMap[Signature, ISet[String]] = mmapEmpty
  /**
   * it's a map from sink API sig to it's category
   */
  protected val sinks: MMap[Signature, (ISet[Int], ISet[String])] = mmapEmpty

  def parse(): Unit = parseFile(sasFilePath)

  def parseFile(sasFile: String): Unit = SSParser.parse(sasFile) match {
    case (srcs, sins) =>
      srcs.foreach{
        case (sig, tags) =>
          this.sources += (sig -> tags)
      }
      sins.foreach{
        case (sig, (poss, tags)) =>
          this.sinks += (sig -> (poss, tags))
      }
  }
  
  def addSource(source: Signature, tags: ISet[String]): Unit = {
    this.sources += (source -> tags)
  }

  def addSink(sink: Signature, positions: ISet[Int], tags: ISet[String]): Unit = {
    this.sinks += (sink -> (positions, tags))
  }
  
  def getSourceAndSinkNode(global: T, node: ICFGNode, pos: Option[Int], ptaresult: PTAResult): (ISet[TaintSource], ISet[TaintSink]) = {
    val sources = msetEmpty[TaintSource]
    val sinks = msetEmpty[TaintSink]
    node match {
      case invNode: ICFGInvokeNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{ callee =>
          val calleeSig = callee.callee
          invNode match {
            case _: ICFGCallNode =>
              global.getMethod(invNode.getOwner) match {
                case Some(caller) =>
                  val jumpLoc = caller.getBody.resolvedBody.locations(invNode.locIndex)
                  if(pos.isEmpty && this.isUISource(global, calleeSig, invNode.getOwner, jumpLoc)) {
                    val tn = TaintSource(TaintNode(invNode, pos), TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
                    sources += tn
                  } else if (pos.isEmpty && this.isSourceMethod(global, calleeSig)) {
                    val tn = TaintSource(TaintNode(invNode, pos), TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
                    sources += tn
                  }
                case None =>
              }
            case _ =>
          }
          invNode match {
            case _: ICFGCallNode if this.isSinkMethod(global, calleeSig) =>
              val poss = this.sinks.filter(sink => matches(global, calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
              pos match {
                case Some(position) =>
                  if (poss.isEmpty || poss.contains(position)) {
                    val tn = TaintSink(TaintNode(invNode, pos), TypeTaintDescriptor(calleeSig.signature, Some(position), SourceAndSinkCategory.API_SINK))
                    sinks += tn
                  }
                case None =>
              }
            case _ =>
          }
        }
      case entNode: ICFGEntryNode =>
        if(this.isEntryPointSource(global, entNode.getOwner)){
          val tn = TaintSource(TaintNode(entNode, pos), TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.ENTRYPOINT_SOURCE))
          sources += tn
        }
        if(pos.isDefined && pos.get > 0 && this.isCallbackSource(global, entNode.getOwner, pos.get - 1)){
          val tn = TaintSource(TaintNode(entNode, pos), TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.CALLBACK_SOURCE))
          sources += tn
        }
      case normalNode: ICFGNormalNode =>
        val owner = global.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.resolvedBody.locations(normalNode.locIndex)
        if(this.isStmtSource(global, loc)){
          val tn = TaintSource(TaintNode(normalNode, pos), TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SOURCE))
          sources += tn
        }
        if(this.isStmtSink(global, loc)){
          val tn = TaintSink(TaintNode(normalNode, pos), TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SINK))
          sinks += tn
        }
      case _ =>
    }
    (sources.toSet, sinks.toSet)
  }

  protected def matches(global: Global, sig1: Signature, methodPool: ISet[Signature]): Boolean = methodPool.exists{ sig2 =>
    val clazz1 = global.getClassOrResolve(sig1.classTyp)
    val typ2 = sig2.classTyp
    sig1.getSubSignature == sig2.getSubSignature && (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }

  protected def matches(global: Global, sig1: Signature, sig2: Signature): Boolean = {
    val clazz1 = global.getClassOrResolve(sig1.classTyp)
    val typ2 = sig2.classTyp
    sig1.getSubSignature == sig2.getSubSignature && (clazz1.typ == typ2 || clazz1.isChildOf(typ2) || clazz1.isImplementerOf(typ2))
  }

  def isStmtSource(global: T, loc: Location): Boolean = false
  def isStmtSink(global: T, loc: Location): Boolean = false

  def isSourceMethod(global: T, sig: Signature): Boolean = matches(global, sig, this.sources.keySet.toSet)
  def isSinkMethod(global: T, sig: Signature): Boolean = matches(global, sig, this.sinks.keySet.toSet)

  def isUISource(global: T, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = false
  def isCallbackSource(global: T, sig: Signature, pos: Int): Boolean = false

  def isEntryPointSource(global: T, sig: Signature): Boolean = false
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object SSParser{
  final val TITLE = "SSParser"
  final val DEBUG = false
  //                           1            2                   3            4
  private val regex = "([^\\s]+)\\s+([^\\s]+)?\\s*->\\s+([^\\s]+)\\s*([^\\s]+)?\\s*"
  def parse(filePath: String): (IMap[Signature, ISet[String]], IMap[Signature, (ISet[Int], ISet[String])]) = {
    val rdr: BufferedReader = new BufferedReader(new FileReader(filePath))
    val sources: MMap[Signature, ISet[String]] = mmapEmpty
    val sinks: MMap[Signature, (ISet[Int], ISet[String])] = mmapEmpty
    val p: Pattern = Pattern.compile(regex)
    var line = rdr.readLine()
    while(line != null){
      try{
        val m = p.matcher(line)
        if(m.find()){
          val (tag, apiSig, positions, tainttags) = parseLine(m)
          tag match{
            case "_SOURCE_" => sources += (apiSig -> tainttags)
            case "_SINK_" => sinks += (apiSig -> (positions, tainttags))
            case "_NONE_" =>
            case _ => throw new RuntimeException("Not expected tag: " + tag)
          }
        } else {
          throw new RuntimeException("Did not match the regex: " + line)
        }
      } catch {
        case ex: Exception =>
          if(DEBUG) ex.printStackTrace()
          System.err.println(TITLE + " exception occurs: " + ex.getMessage)
      }
      line = rdr.readLine()
    }
    rdr.close()
    (sources.toMap, sinks.toMap)
  }
  
  def parseLine(m: Matcher): (String, Signature, ISet[Int], ISet[String]) = {
    require(m.group(1) != null && m.group(3) != null)
    val apiSig = new Signature(m.group(1))
    val taintTag = m.group(2)
    val taintTags: ISet[String] = if(taintTag == null) isetEmpty else taintTag.split("\\|").toSet
    val tag = m.group(3)
    val rawpos = m.group(4)
    val positions: MSet[Int] = msetEmpty
    if(rawpos != null) {
      positions ++= rawpos.split("\\|").map(_.toInt)
    }
    (tag, apiSig, positions.toSet, taintTags)
  }
}
