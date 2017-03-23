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

import org.sireum.util._
import akka.actor._
import akka.routing.FromConfig

import scala.concurrent.duration._
import com.typesafe.config.Config
import akka.dispatch.UnboundedPriorityMailbox
import akka.dispatch.PriorityGenerator
import org.argus.amandroid.concurrent.util.Recorder

import scala.language.postfixOps

class AmandroidSupervisorActor(recorder: Recorder) extends Actor with ActorLogging {
  private val decActor = context.actorOf(FromConfig.props(Props[DecompilerActor]), "DecompilerActor")
  private val apkInfoColActor = context.actorOf(FromConfig.props(Props[ApkInfoCollectActor]), "ApkInfoCollectorActor")
  private val ptaActor = context.actorOf(FromConfig.props(Props[PointsToAnalysisActor]), "PointsToAnalysisActor")
  private val seActor = context.actorOf(FromConfig.props(Props[SecurityEngineActor]), "SecurityEngineActor")
  private val sendership: MMap[FileResourceUri, ActorRef] = mmapEmpty
  def receive: Receive = {
    case as: AnalysisSpec =>
      sendership(as.fileUri) = sender
      decActor ! DecompileData(as.fileUri, as.outputUri, as.dpsuri, as.removeSupportGen, as.forceDelete, 30 minutes)
    case dr: DecompilerResult =>
      dr match {
        case dsr: DecompileSuccResult =>
          recorder.decompile(FileUtil.toFile(dsr.fileUri).getName, succ = true)
          apkInfoColActor ! ApkInfoCollectData(dsr.fileUri, dsr.outApkUri, dsr.srcFolders, 30 minutes)
        case dfr: DecompileFailResult =>
          recorder.decompile(FileUtil.toFile(dfr.fileUri).getName, succ = false)
          log.error(dfr.e, "Decompile fail on " + dfr.fileUri)
          sendership(dfr.fileUri) ! dfr
          sendership -= dfr.fileUri
      }
    case aicr: ApkInfoCollectResult =>
      aicr match {
        case aicsr: ApkInfoCollectSuccResult =>
          recorder.infocollect(FileUtil.toFile(aicsr.fileUri).getName, succ = true)
          ptaActor ! PointsToAnalysisData(aicsr.model, aicsr.outApkUri, aicsr.srcFolders, PTAAlgorithms.RFA, stage = true, timeoutForeachComponent = 5 minutes)
        case aicfr: ApkInfoCollectFailResult =>
          recorder.infocollect(FileUtil.toFile(aicfr.fileUri).getName, succ = false)
          log.error(aicfr.e, "Information collect failed on " + aicfr.fileUri)
          sendership(aicfr.fileUri) ! aicfr
          sendership -= aicfr.fileUri
      }
    case ptar: PointsToAnalysisResult =>
      ptar match {
        case ptsr: PointsToAnalysisSuccResult =>
          log.info("Points to analysis success for " + ptsr.fileUri)
          recorder.pta(FileUtil.toFile(ptsr.fileUri).getName, ptar.time, succ = true)
        case ptssr: PointsToAnalysisSuccStageResult =>
          recorder.pta(FileUtil.toFile(ptssr.fileUri).getName, ptar.time, succ = true)
          log.info("Points to analysis success staged for " + ptssr.fileUri)
        case ptfr: PointsToAnalysisFailResult =>
          recorder.pta(FileUtil.toFile(ptfr.fileUri).getName, ptar.time, succ = false)
          log.error(ptfr.e, "Points to analysis failed on " + ptfr.fileUri)
      }
      sendership(ptar.fileUri) ! ptar
      sendership -= ptar.fileUri
    case sed: SecurityEngineData =>
      sendership(sed.ptar.fileUri) = sender
      seActor ! sed
    case ser: SecurityEngineResult =>
      ser match {
        case sesr: SecurityEngineSuccResult =>
          log.info("Security analysis success for " + sesr.fileUri)
        case sefr: SecurityEngineFailResult =>
          log.error(sefr.e, "Security analysis failed on " + sefr.fileUri)
      }
      sendership(ser.fileUri) ! ser
      sendership -= ser.fileUri
  }
}

class AmandroidSupervisorActorPrioMailbox(settings: ActorSystem.Settings, config: Config) extends UnboundedPriorityMailbox(
    // Create a new PriorityGenerator, lower prio means more important
    PriorityGenerator {
      case AnalysisSpec => 3
      case _: DecompilerResult => 2
      case _: ApkInfoCollectResult => 1
      case _: PointsToAnalysisResult => 0
      case _: SecurityEngineData => 3
      case _: SecurityEngineResult => 0
      case _ => 4
    })
