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

import akka.actor._
import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.concurrent.util.GlobalUtil
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult, TaintAnalysisModules}
import org.argus.amandroid.serialization.stage.Staging
import org.argus.jawa.alir.pta.BuildICFGFromExistingPTAResult
import org.argus.jawa.core.{MsgLevel, PrintReporter, Signature}
import org.sireum.util._

trait SecSpec
case class TaintAnalysisSpec(module: TaintAnalysisModules.Value) extends SecSpec
case class APIMisconfigureSpec(checker: ApiMisuseChecker) extends SecSpec

trait SecResult
case class TaintAnalysisResult(outApkUri: FileResourceUri) extends SecResult
case class APIMisconfigureResult(outApkUri: FileResourceUri) extends SecResult

class SecurityEngineActor extends Actor with ActorLogging {
  def receive: Receive = {
    case secdata: SecurityEngineData =>
      sender ! sec(secdata)
  }
  
  def sec(secdata: SecurityEngineData): SecurityEngineResult = {
    var res: SecurityEngineResult = null
    try {
      val (apk, ptaresults) =
        secdata.ptar match {
          case ptas: PointsToAnalysisSuccResult =>
            (ptas.apk, ptas.ptaresults)
          case ptass: PointsToAnalysisSuccStageResult =>
            Staging.recoverStage(ptass.outApkUri)
        }
      val reporter = new PrintReporter(MsgLevel.ERROR)
      val global = GlobalUtil.buildGlobal(apk.nameUri, reporter, apk.outApkUri, apk.srcs)
      apk.resolveEnvInGlobal(global)
      val idfgs = BuildICFGFromExistingPTAResult(global, ptaresults)
      secdata.spec match {
        case ta: TaintAnalysisSpec =>
          val ssm = ta.module match {
            case TaintAnalysisModules.INTENT_INJECTION =>
              new IntentInjectionSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.PASSWORD_TRACKING =>
              new PasswordSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.OAUTH_TOKEN_TRACKING =>
              new OAuthSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.DATA_LEAKAGE => 
              new DataLeakageAndroidSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
            case TaintAnalysisModules.COMMUNICATION_LEAKAGE =>
              new CommunicationSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
          }
          val yard = new ApkYard(global)
          yard.addApk(apk)
          val cba = new ComponentBasedAnalysis(global, yard)
          cba.phase1(apk, parallel = false, idfgs)
          val iddResult = cba.phase2(Set(apk), parallel = false)
          val tar = cba.phase3(iddResult, ssm)
          tar match {
            case Some(tres) => 
              Staging.stageTaintAnalysisResult(tres.toTaintAnalysisSimpleResult, apk.outApkUri)
              res = SecurityEngineSuccResult(secdata.ptar.fileUri, Some(TaintAnalysisResult(apk.outApkUri)))
            case None =>
              res = SecurityEngineSuccResult(secdata.ptar.fileUri, None)
          }
        case am: APIMisconfigureSpec =>
          val misusedApis: MMap[(Signature, String), String] = mmapEmpty
          idfgs foreach {
            case (sig, idfg) => 
              val result = am.checker.check(global, Some(idfg))
              misusedApis ++= result.misusedApis
          }
          Staging.stageAPIMisuseResult(ApiMisuseResult(misusedApis.toMap), apk.outApkUri)
          res = SecurityEngineSuccResult(secdata.ptar.fileUri, Some(APIMisconfigureResult(apk.outApkUri)))
      }
      
    } catch {
      case e: Exception =>
        res = SecurityEngineFailResult(secdata.ptar.fileUri, e)
    }
    res
  }
}