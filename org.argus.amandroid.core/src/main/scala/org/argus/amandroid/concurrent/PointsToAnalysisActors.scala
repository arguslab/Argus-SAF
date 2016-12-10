/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.concurrent

import java.util.concurrent.TimeoutException

import akka.actor._
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidRFAConfig, AndroidReachingFactsAnalysis}
import org.argus.amandroid.concurrent.util.GlobalUtil
import org.argus.amandroid.core.Apk
import org.argus.amandroid.serialization.stage.Staging
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFactFactory
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.{ClassLoadManager, MsgLevel, PrintReporter, Signature}
import org.sireum.util._

import scala.concurrent.duration._

object PTAAlgorithms extends Enumeration {
  val SUPER_SPARK, RFA = Value
}

class PointsToAnalysisActor extends Actor with ActorLogging {
  
  def receive: Receive = {
    case ptadata: PointsToAnalysisData =>
      sender ! pta(ptadata)
  }
  
  private def pta(ptadata: PointsToAnalysisData): PointsToAnalysisResult = {
    log.info("Start points to analysis for " + ptadata.apk.nameUri)
    val apk = ptadata.apk
    val components = apk.getComponents
    val worklist: MList[Signature] = mlistEmpty
    components foreach {
      compTyp =>
        apk.getEnvMap.get(compTyp) match {
          case Some((esig, _)) =>
            worklist += esig
          case None =>
            log.error("Component " + compTyp.name + " did not have environment! Some package or name mismatch maybe in the Manifestfile.")
        }
    }
    val ptaresults: MMap[Signature, PTAResult] = mmapEmpty
    val succEps: MSet[Signature] = msetEmpty
    var time = System.currentTimeMillis()
    while(worklist.nonEmpty) {
      val esig = worklist.remove(0)
      try {
        val res = rfa(esig, apk, ptadata.outApkUri, ptadata.srcFolders, ptadata.timeoutForeachComponent)
        ptaresults(esig) = res.ptaresult
        succEps += esig
      } catch {
        case _: TimeoutException =>
          log.warning("PTA timeout for " + esig)
        case e: Exception =>
          log.error(e, "PTA failed for " + esig)
      }
    }
    time = (System.currentTimeMillis() - time) / 1000
    if(ptadata.stage) {
      try {
        Staging.stage(apk, ptaresults.toMap, ptadata.outApkUri)
        val outUri = FileUtil.toUri(FileUtil.toFile(ptadata.outApkUri).getParentFile)
        Staging.stageReport(outUri, apk.getAppName)
        PointsToAnalysisSuccStageResult(apk.nameUri, time, ptadata.outApkUri)
      } catch {
        case e: Exception =>
          PointsToAnalysisFailResult(apk.nameUri, time, e)
      }
    } else {
      PointsToAnalysisSuccResult(apk, time, ptaresults.toMap)
    }
    
  }
  
  private def rfa(ep: Signature, apk: Apk, outApkUri: FileResourceUri, srcs: ISet[String], timeout: Duration): InterproceduralDataFlowGraph = {
    log.info("Start rfa for " + ep)
    val reporter = new PrintReporter(MsgLevel.ERROR)
    val global = GlobalUtil.buildGlobal(apk.nameUri, reporter, outApkUri, srcs)
    val m = global.resolveMethodCode(ep, apk.getEnvMap(ep.classTyp)._2)
    implicit val factory = new RFAFactFactory
    val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(m)
    val idfg = AndroidReachingFactsAnalysis(global, apk, m, initialfacts, new ClassLoadManager, timeout = timeout match{case fd: FiniteDuration => Some(new MyTimeout(fd)) case _ => None })
    idfg
  }
  
}