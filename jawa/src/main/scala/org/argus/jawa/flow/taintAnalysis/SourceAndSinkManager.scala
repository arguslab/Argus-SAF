/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.taintAnalysis

import org.argus.jawa.core.util._
import java.io.BufferedReader
import java.io.FileReader
import java.util.Scanner
import java.util.regex.Pattern
import java.util.regex.Matcher

import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.core.ast.Location
import org.argus.jawa.core.Global
import org.argus.jawa.core.elements.Signature

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

  protected val customSinks: MMap[String, MMap[Signature, (ISet[SSPosition], ISet[String])]] = mmapEmpty
  def addCustomSink(key: String, sourceSig: Signature, positions: ISet[Int], tags: ISet[String]): Unit = this.customSinks.getOrElseUpdate(key, mmapEmpty) +=  (sourceSig -> (positions.map(p => new SSPosition(p)), tags))
  def getCustomSinks(key: String): IMap[Signature,  (ISet[SSPosition], ISet[String])] = this.customSinks.getOrElse(key, mmapEmpty).toMap
  
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
              this.isSourceMethod(global, calleeSig) match {
                case Some((tag, poss)) =>
                  if(poss.isEmpty) {
                    if(pos.isEmpty) {
                      sources += TaintSource(TaintNode(invNode, None), TypeTaintDescriptor(calleeSig.signature, None, tag))
                    }
                  } else {
                    pos match {
                      case Some(position) =>
                        poss.foreach { p =>
                          if(p.pos == position) {
                            sources += TaintSource(TaintNode(invNode, Some(p)), TypeTaintDescriptor(calleeSig.signature, Some(p), tag))
                          }
                        }
                      case None =>
                    }
                  }
                case None =>
              }
            case _ =>
          }
          invNode match {
            case _: ICFGCallNode =>
              this.isSinkMethod(global, calleeSig) match {
                case Some((tag, poss)) =>
                  pos match {
                    case Some(position) =>
                      if(poss.isEmpty) {
                        sinks += TaintSink(TaintNode(invNode, Some(new SSPosition(s"$position"))), TypeTaintDescriptor(calleeSig.signature, Some(new SSPosition(position)), tag))
                      } else {
                        poss.foreach { p =>
                          if(p.pos == position) {
                            sinks += TaintSink(TaintNode(invNode, Some(p)), TypeTaintDescriptor(calleeSig.signature, Some(p), tag))
                          }
                        }
                      }
                    case None =>
                  }
                case None =>
              }
            case _ =>
          }
        }
      case entNode: ICFGEntryNode =>
        if(pos.isDefined && pos.get > 0 && this.isEntryPointSource(global, entNode.getOwner)){
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

  def isSourceMethod(global: T, sig: Signature): Option[(String, ISet[SSPosition])] = {
    val srcs = this.sources.filter(source => matches(global, sig, source._1))
    val poss = srcs.map(_._2._1).fold(isetEmpty)(iunion)
    if(srcs.nonEmpty) {
      Some((SourceAndSinkCategory.API_SOURCE, poss))
    } else {
      None
    }
  }
  def isSinkMethod(global: T, sig: Signature): Option[(String, ISet[SSPosition])] = {
    val sinks = this.sinks.filter(sink => matches(global, sig, sink._1))
    val poss = sinks.map(_._2._1).fold(isetEmpty)(iunion)
    if(sinks.nonEmpty) {
      Some((SourceAndSinkCategory.API_SINK, poss))
    } else {
      None
    }
  }

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
