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
import java.util.Scanner
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
  protected val sources: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty
  /**
   * it's a map from sink API sig to it's category
   */
  protected val sinks: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty

  def parse(): Unit = parseFile(sasFilePath)

  def parseFile(sasFile: String): Unit = SSParser.parseFile(sasFile) match {
    case (srcs, sins) =>
      this.sources ++= srcs
      this.sinks ++= sins
  }

  def parseCode(code: String): Unit = SSParser.parseCode(code) match {
    case (srcs, sins) =>
      this.sources ++= srcs
      this.sinks ++= sins
  }
  
  def addSource(source: Signature, positions: ISet[SSPosition], tags: ISet[String]): Unit = {
    this.sources += (source -> (positions, tags))
  }

  def addSink(sink: Signature, positions: ISet[SSPosition], tags: ISet[String]): Unit = {
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
                    sources += TaintSource(TaintNode(invNode, None), TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
                  }
                case None =>
              }
              if(this.isSourceMethod(global, calleeSig)) {
                val poss: ISet[SSPosition] = this.sources.filter(source => matches(global, calleeSig, source._1)).map(_._2._1).fold(isetEmpty)(iunion)
                if(poss.isEmpty) {
                  if(pos.isEmpty) {
                    sources += TaintSource(TaintNode(invNode, None), TypeTaintDescriptor(calleeSig.signature, None, SourceAndSinkCategory.API_SOURCE))
                  }
                } else {
                  pos match {
                    case Some(position) =>
                      poss.foreach { p =>
                        if(p.pos == position) {
                          sources += TaintSource(TaintNode(invNode, Some(p)), TypeTaintDescriptor(calleeSig.signature, Some(p), SourceAndSinkCategory.API_SOURCE))
                        }
                      }
                    case None =>
                  }
                }
              }
            case _ =>
          }
          invNode match {
            case _: ICFGCallNode if this.isSinkMethod(global, calleeSig) =>
              val poss: ISet[SSPosition] = this.sinks.filter(sink => matches(global, calleeSig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
              pos match {
                case Some(position) =>
                  if(poss.isEmpty) {
                    sinks += TaintSink(TaintNode(invNode, Some(new SSPosition(s"$position"))), TypeTaintDescriptor(calleeSig.signature, Some(new SSPosition(position)), SourceAndSinkCategory.API_SINK))
                  } else {
                    poss.foreach { p =>
                      if(p.pos == position) {
                        sinks += TaintSink(TaintNode(invNode, Some(p)), TypeTaintDescriptor(calleeSig.signature, Some(p), SourceAndSinkCategory.API_SINK))
                      }
                    }
                  }
                case None =>
              }
            case _ =>
          }
        }
      case entNode: ICFGEntryNode =>
        if(this.isEntryPointSource(global, entNode.getOwner)){
          sources += TaintSource(TaintNode(entNode, pos.map(new SSPosition(_))), TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.ENTRYPOINT_SOURCE))
        }
        if(pos.isDefined && pos.get > 0 && this.isCallbackSource(global, entNode.getOwner, pos.get - 1)){
          sources += TaintSource(TaintNode(entNode, pos.map(new SSPosition(_))), TypeTaintDescriptor(entNode.getOwner.signature, None, SourceAndSinkCategory.CALLBACK_SOURCE))
        }
      case normalNode: ICFGNormalNode =>
        val owner = global.getMethod(normalNode.getOwner).get
        val loc = owner.getBody.resolvedBody.locations(normalNode.locIndex)
        if(this.isStmtSource(global, loc)){
          val tn = TaintSource(TaintNode(normalNode, pos.map(new SSPosition(_))), TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SOURCE))
          sources += tn
        }
        if(this.isStmtSink(global, loc)){
          val tn = TaintSink(TaintNode(normalNode, pos.map(new SSPosition(_))), TypeTaintDescriptor(normalNode.getOwner.signature, None, SourceAndSinkCategory.STMT_SINK))
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

class SSPosition(str: String) {
  def this(i: Int) = this(s"$i")
  private val parts = str.split("\\.").toList
  def pos: Int = parts.head.toInt
  def fields: IList[String] = parts.tail

  override def toString: FileResourceUri = str
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
  def parseFile(filePath: String): (IMap[Signature, (ISet[SSPosition], ISet[String])], IMap[Signature, (ISet[SSPosition], ISet[String])]) = {
    val rdr: BufferedReader = new BufferedReader(new FileReader(filePath))
    val sources: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty
    val sinks: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty
    val p: Pattern = Pattern.compile(regex)
    var line = rdr.readLine()
    while(line != null){
      try{
        val m = p.matcher(line)
        if(m.find()){
          val (tag, apiSig, positions, tainttags) = parseLine(m)
          tag match{
            case "_SOURCE_" => sources += (apiSig -> (positions.map(p => new SSPosition(p)), tainttags))
            case "_SINK_" => sinks += (apiSig -> (positions.map(p => new SSPosition(p)), tainttags))
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

  def parseCode(code: String): (IMap[Signature, (ISet[SSPosition], ISet[String])], IMap[Signature, (ISet[SSPosition], ISet[String])]) = {
    val sc: Scanner = new Scanner(code)
    val sources: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty
    val sinks: MMap[Signature, (ISet[SSPosition], ISet[String])] = mmapEmpty
    val p: Pattern = Pattern.compile(regex)
    while(sc.hasNextLine){
      val line = sc.nextLine()
      try{
        val m = p.matcher(line)
        if(m.find()){
          val (tag, apiSig, positions, tainttags) = parseLine(m)
          tag match{
            case "_SOURCE_" => sources += (apiSig -> (positions.map(p => new SSPosition(p)), tainttags))
            case "_SINK_" => sinks += (apiSig -> (positions.map(p => new SSPosition(p)), tainttags))
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
    }
    (sources.toMap, sinks.toMap)
  }
  
  def parseLine(m: Matcher): (String, Signature, ISet[String], ISet[String]) = {
    require(m.group(1) != null && m.group(3) != null)
    val apiSig = new Signature(m.group(1))
    val taintTag = m.group(2)
    val taintTags: ISet[String] = if(taintTag == null) isetEmpty else taintTag.split("\\|").toSet
    val tag = m.group(3)
    val rawpos = m.group(4)
    val positions: MSet[String] = msetEmpty
    if(rawpos != null) {
      positions ++= rawpos.split("\\|")
    }
    (tag, apiSig, positions.toSet, taintTags)
  }
}
