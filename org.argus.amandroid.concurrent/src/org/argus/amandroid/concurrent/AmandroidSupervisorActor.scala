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

import org.sireum.util._
import akka.actor._
import akka.routing.FromConfig

import scala.concurrent.duration._
import com.typesafe.config.Config
import akka.dispatch.UnboundedPriorityMailbox
import akka.dispatch.PriorityGenerator
import com.typesafe.config.ConfigFactory

import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import akka.pattern.ask
import org.argus.amandroid.plugin.TaintAnalysisModules

class AmandroidSupervisorActor extends Actor with ActorLogging {
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
          apkInfoColActor ! ApkInfoCollectData(dsr.fileUri, dsr.outApkUri, dsr.srcFolders, 30 minutes)
        case dfr: DecompileFailResult =>
          log.error(dfr.e, "Decompile fail on " + dfr.fileUri)
      }
    case aicr: ApkInfoCollectResult =>
      aicr match {
        case aicsr: ApkInfoCollectSuccResult =>
          ptaActor ! PointsToAnalysisData(aicsr.apk, aicsr.outApkUri, aicsr.srcFolders, PTAAlgorithms.RFA, stage = true, timeoutForeachComponent = 10 minutes)
        case aicfr: ApkInfoCollectFailResult =>
          log.error(aicfr.e, "Infomation collect failed on " + aicfr.fileUri)
          sendership(aicfr.fileUri) ! aicfr
          sendership -= aicfr.fileUri
      }
    case ptar: PointsToAnalysisResult =>
      ptar match {
        case ptsr: PointsToAnalysisSuccResult =>
          log.info("Points to analysis success for " + ptsr.fileUri)
        case ptssr: PointsToAnalysisSuccStageResult =>
          log.info("Points to analysis success staged for " + ptssr.fileUri)
        case ptfr: PointsToAnalysisFailResult =>
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
      case dr: DecompilerResult => 2
      case aicr: ApkInfoCollectResult => 1
      case ptar: PointsToAnalysisResult => 0
      case sed: SecurityEngineData => 3
      case ser: SecurityEngineResult => 0
      case otherwise => 4
    })

object AmandroidTestApplication extends App {
  val _system = ActorSystem("AmandroidTestApplication", ConfigFactory.load)
  val supervisor = _system.actorOf(Props[AmandroidSupervisorActor], name = "AmandroidSupervisorActor")
  val fileUris = FileUtil.listFiles(FileUtil.toUri(args(0)), ".apk", recursive = true)
  val outputUri = FileUtil.toUri(args(1))
  val futures = fileUris map {
    fileUri =>
      supervisor.ask(AnalysisSpec(fileUri, outputUri, None, removeSupportGen = true, forceDelete = true))(600 minutes).mapTo[PointsToAnalysisResult].recover{
        case ex: Exception => 
            PointsToAnalysisFailResult(fileUri, ex)
        }
  }
  val fseq = Future.sequence(futures)
  val seFutures: MSet[Future[SecurityEngineResult]] = msetEmpty
  Await.result(fseq, Duration.Inf).foreach {
    case ptar: PointsToAnalysisResult with Success =>
      seFutures += supervisor.ask(SecurityEngineData(ptar, TaintAnalysisSpec(TaintAnalysisModules.DATA_LEAKAGE)))(10 minutes).mapTo[SecurityEngineResult].recover {
        case ex: Exception =>
          SecurityEngineFailResult(ptar.fileUri, ex)
      }
    case _ =>
  }
  val sefseq = Future.sequence(seFutures)
  Await.result(sefseq, Duration.Inf).foreach {
    sr => println(sr)
  }
  _system.terminate()
}
