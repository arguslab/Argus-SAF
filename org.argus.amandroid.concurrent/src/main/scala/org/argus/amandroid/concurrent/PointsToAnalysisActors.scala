/*
 * Copyright (c) 2017. Fengguo Wei and others.
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
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.serialization.stage.Staging
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFactFactory
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.{ClassLoadManager, MsgLevel, PrintReporter, Signature}
import org.argus.jawa.core.util._

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
    log.info("Start points to analysis for " + ptadata.model.nameUri)
    val model = ptadata.model
    val apk = new ApkGlobal(model, new PrintReporter(MsgLevel.ERROR))
    apk.load()
    val components = model.getComponents
    val worklist: MList[Signature] = mlistEmpty
    components foreach {
      compTyp =>
        model.getEnvMap.get(compTyp) match {
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
        val res = rfa(esig, apk, ptadata.timeoutForeachComponent)
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
        Staging.stage(model, ptaresults.toMap)
        val outUri = FileUtil.toUri(FileUtil.toFile(model.layout.outputSrcUri).getParentFile)
        Staging.stageReport(outUri, model.getAppName)
        PointsToAnalysisSuccStageResult(model.nameUri, time, model.getComponentInfos.size, model.layout.outputSrcUri)
      } catch {
        case e: Exception =>
          PointsToAnalysisFailResult(model.nameUri, time, model.getComponentInfos.size, e)
      }
    } else {
      PointsToAnalysisSuccResult(model, time, model.getComponentInfos.size, ptaresults.toMap)
    }
    
  }
  
  private def rfa(ep: Signature, apk: ApkGlobal, timeout: Duration): InterproceduralDataFlowGraph = {
    log.info("Start rfa for " + ep)
    val m = apk.resolveMethodCode(ep, apk.model.getEnvMap(ep.classTyp)._2)
    implicit val factory = new RFAFactFactory
    val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(m)
    val idfg = AndroidReachingFactsAnalysis(apk, m, initialfacts, new ClassLoadManager, new Context(apk.projectName), timeout = timeout match{case fd: FiniteDuration => Some(new MyTimeout(fd)) case _ => None })
    idfg
  }
  
}