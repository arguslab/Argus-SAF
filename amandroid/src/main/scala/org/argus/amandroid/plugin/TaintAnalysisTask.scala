/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.store.TaintStore
import org.argus.jawa.flow.summary.taint.BottomUpTaintAnalysis

import scala.concurrent.duration._
import scala.language.postfixOps

object TaintAnalysisApproach extends Enumeration {
  val COMPONENT_BASED, BOTTOM_UP = Value
}

case class TaintAnalysisTask(module: TaintAnalysisModules.Value, fileUris: ISet[(FileResourceUri, FileResourceUri)], forceDelete: Boolean, reporter: Reporter, guessPackage: Boolean, approach: TaintAnalysisApproach.Value) {
  import TaintAnalysisModules._
//  private final val TITLE = "TaintAnalysisTask"
  def run: Option[TaintAnalysisResult] = {
    val yard = new ApkYard(reporter)
    val apks = fileUris.map{ case (apkUri, outputUri) =>
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = forceDelete, strategy, reporter)
      yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true, guessPackage)
    }
    val ssm = module match {
      case INTENT_INJECTION =>
        new IntentInjectionSourceAndSinkManager(AndroidGlobalConfig.settings.injection_sas_file)
      case PASSWORD_TRACKING =>
        new PasswordSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case OAUTH_TOKEN_TRACKING =>
        new OAuthSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case DATA_LEAKAGE =>
        new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
      case COMMUNICATION_LEAKAGE =>
        new CommunicationSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
    }
    approach match {
      case TaintAnalysisApproach.BOTTOM_UP =>
        var tar: Option[TaintStore] = None
        apks.foreach { apk =>
          val ta = new BottomUpTaintAnalysis[ApkGlobal](apk, new AndroidSummaryProvider(apk), new AndroidModelCallHandler, ssm, reporter)
          val eps = apk.model.getEnvMap.map(_._2._1).toSet
          val taintMap = ta.process(eps)
          taintMap.foreach { case (_, t) =>
            tar match {
              case Some(ts) =>
                ts.merge(t)
              case None =>
                tar = Some(t)
                apk.addTaintAnalysisResult(t)
            }
          }
        }
        writeResult(apks)
        tar
      case TaintAnalysisApproach.COMPONENT_BASED =>
        ComponentBasedAnalysis.prepare(apks)(AndroidGlobalConfig.settings.timeout minutes)
        val cba = new ComponentBasedAnalysis(yard)
        cba.phase1(apks)
        val iddResult = cba.phase2(apks)
        val tar = cba.phase3(iddResult, ssm)
        writeResult(apks)
        tar
    }
  }

  private def writeResult(apks: ISet[ApkGlobal]): Unit = {
    apks.foreach { apk =>
      val appData = DataCollector.collect(apk)
      val outputDirUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "result")
      val outputDir = FileUtil.toFile(outputDirUri)
      if (!outputDir.exists()) outputDir.mkdirs()
      val out = new PrintWriter(FileUtil.toFile(FileUtil.appendFileName(outputDirUri, "AppData.txt")))
      out.print(appData.toString)
      out.close()
    }
  }
}