/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary

import com.google.common.base.Charsets
import com.google.common.io.Resources
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.susaf.HeapSummaryProcessor
import org.argus.jawa.summary.susaf.parser.SummaryParser
import org.argus.jawa.summary.susaf.rule.HeapSummary

import scala.reflect.{ClassTag, classTag}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryManager(global: Global)(implicit heap: SimHeap) {

  //  Map from signature to Summary
  private val summaries: MMap[Signature, MSet[Summary]] = mmapEmpty
  private val heapSummariesMatchFileAndSubsig: MMap[String, IMap[String, HeapSummary]] = mmapEmpty

  def register(signature: Signature, summary: Summary): Unit = summaries.getOrElseUpdate(signature, msetEmpty) += summary

  def register(name: String, suCode: String, fileAndSubsigMatch: Boolean): IMap[Signature, Summary] = {
    val su = SummaryParser(suCode)
    su.defaultTypes.foreach { case (baseType, fields) =>
      HeapSummaryProcessor.addDefaultTypes(global, baseType, fields)
    }
    if(fileAndSubsigMatch) {
      val s = su.summaries.map{ case (k, v) => k.getSubSignature -> v}
      this.heapSummariesMatchFileAndSubsig(name) = s
    } else {
      su.summaries.foreach { case (signature, summary) =>
        register(signature, summary)
      }
    }
    su.summaries
  }

  def contains(sig: Signature): Boolean = summaries.contains(sig)
  def contains(file: String, subsig: String): Boolean = heapSummariesMatchFileAndSubsig.get(file) match {
    case Some(map) => map.contains(subsig)
    case None => false
  }

  def getSummaries(sig: Signature): ISet[Summary] = summaries.getOrElse(sig, msetEmpty).toSet

  def getSummary[T <: Summary : ClassTag](sig: Signature): Option[T] = {
    summaries.get(sig) match {
      case Some(sus) =>
        sus.foreach {
          case t if classTag[T].runtimeClass.isInstance(t) => return Some(t.asInstanceOf[T])
          case _ =>
        }
        None
      case None => None
    }
  }

  def registerFile(safsuPath: String, name: String, fileAndSubsigMatch: Boolean): Unit = {
    val url = Resources.getResource(safsuPath)
    val code = Resources.toString(url, Charsets.UTF_8)
    register(name, code, fileAndSubsigMatch)
  }

  def getSummariesByFile(name: String): IMap[String, HeapSummary] = {
    this.heapSummariesMatchFileAndSubsig.getOrElse(name, imapEmpty)
  }
}