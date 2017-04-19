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

import akka.actor._
import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.concurrent.util.GlobalUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult, TaintAnalysisModules}
import org.argus.amandroid.serialization.stage.Staging
import org.argus.jawa.alir.pta.BuildICFGFromExistingPTAResult
import org.argus.jawa.core.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._

trait SecSpec
case class TaintAnalysisSpec(module: TaintAnalysisModules.Value) extends SecSpec
case class APIMisconfigureSpec(checker: ApiMisuseChecker) extends SecSpec

trait SecResult
case class TaintAnalysisResult(outApkUri: FileResourceUri) extends SecResult
case class APIMisConfigureResult(outApkUri: FileResourceUri) extends SecResult

class SecurityEngineActor extends Actor with ActorLogging {
  def receive: Receive = {
    case secdata: SecurityEngineData =>
      sender ! sec(secdata)
  }

  def sec(secdata: SecurityEngineData): SecurityEngineResult = {
    var res: SecurityEngineResult = null
    try {
      val (model, pta_results) =
        secdata.ptar match {
          case ptas: PointsToAnalysisSuccResult =>
            (ptas.model, ptas.ptaresults)
          case ptass: PointsToAnalysisSuccStageResult =>
            Staging.recoverStage(ptass.outApkUri)
        }
      val reporter = new PrintReporter(MsgLevel.ERROR)
      val apk = new ApkGlobal(model, reporter)
      GlobalUtil.buildGlobal(apk, apk.model.outApkUri, apk.model.srcs)
      apk.resolveEnvInGlobal()
      val idfgs = BuildICFGFromExistingPTAResult(apk, pta_results)
      idfgs.foreach { case (typ, idfg) =>
        apk.addIDFG(typ, idfg)
      }
      secdata.spec match {
        case ta: TaintAnalysisSpec =>
          val ssm = ta.module match {
            case TaintAnalysisModules.INTENT_INJECTION =>
              new IntentInjectionSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.PASSWORD_TRACKING =>
              new PasswordSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.OAUTH_TOKEN_TRACKING =>
              new OAuthSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.DATA_LEAKAGE =>
              new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.COMMUNICATION_LEAKAGE =>
              new CommunicationSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
          }
          val yard = new ApkYard(reporter)
          yard.addApk(apk)
          val cba = new ComponentBasedAnalysis(yard)
          cba.phase1(Set(apk))
          val iddResult = cba.phase2(Set(apk))
          val tar = cba.phase3(iddResult, ssm)
          tar match {
            case Some(tres) =>
              Staging.stageTaintAnalysisResult(tres.toTaintAnalysisSimpleResult, apk.model.outApkUri)
              res = SecurityEngineSuccResult(secdata.ptar.fileUri, Some(TaintAnalysisResult(apk.model.outApkUri)))
            case None =>
              res = SecurityEngineSuccResult(secdata.ptar.fileUri, None)
          }
        case am: APIMisconfigureSpec =>
          val misusedApis: MMap[(String, String), String] = mmapEmpty
          idfgs foreach {
            case (_, idfg) =>
              val result = am.checker.check(apk, Some(idfg))
              misusedApis ++= result.misusedApis
          }
          Staging.stageAPIMisuseResult(ApiMisuseResult(am.checker.name, misusedApis.toMap), apk.model.outApkUri)
          res = SecurityEngineSuccResult(secdata.ptar.fileUri, Some(APIMisConfigureResult(apk.model.outApkUri)))
      }
      
    } catch {
      case e: Exception =>
        res = SecurityEngineFailResult(secdata.ptar.fileUri, e)
    }
    res
  }
}