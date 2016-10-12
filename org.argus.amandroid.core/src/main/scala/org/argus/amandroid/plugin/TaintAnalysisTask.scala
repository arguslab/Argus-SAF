/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceAnalysis
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.Global
import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util._

import scala.concurrent.duration._

object TaintAnalysisModules extends Enumeration {
  val INTENT_INJECTION, PASSWORD_TRACKING, OAUTH_TOKEN_TRACKING, DATA_LEAKAGE, COMMUNICATION_LEAKAGE = Value
}

case class TaintAnalysisTask(global: Global, module: TaintAnalysisModules.Value, fileUri: FileResourceUri, outputUri: FileResourceUri, dpsuri: Option[FileResourceUri], forceDelete: Boolean) {
  import TaintAnalysisModules._
//  private final val TITLE = "TaintAnalysisTask"
  def run: Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterproceduralDataDependenceAnalysis.Edge]] = {
    val yard = new ApkYard(global)
    val layout = DecompileLayout(outputUri)
    val settings = DecompilerSettings(dpsuri, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = forceDelete, None, layout)
    val apk = yard.loadApk(fileUri, settings)
    val ssm = module match {
      case INTENT_INJECTION =>
        new IntentInjectionSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
      case PASSWORD_TRACKING =>
        new PasswordSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
      case OAUTH_TOKEN_TRACKING =>
        new OAuthSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
      case DATA_LEAKAGE =>
        new DataLeakageAndroidSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
      case COMMUNICATION_LEAKAGE =>
        new CommunicationSourceAndSinkManager(global, apk, apk.getLayoutControls, apk.getCallbackMethods, AndroidGlobalConfig.settings.sas_file)
    }
    val idfgs = ComponentBasedAnalysis.prepare(global, apk, parallel = false)(AndroidGlobalConfig.settings.timeout minutes)
    val cba = new ComponentBasedAnalysis(global, yard)
    cba.phase1(apk, parallel = false, idfgs)
    val iddResult = cba.phase2(Set(apk), parallel = false)
    val tar = cba.phase3(iddResult, ssm)
    val appData = DataCollector.collect(global, yard, apk)
    val outUri = ApkFileUtil.getOutputUri(fileUri, outputUri)
    val outputDirUri = MyFileUtil.appendFileName(outUri, "result")
    val outputDir = FileUtil.toFile(outputDirUri)
    if(!outputDir.exists()) outputDir.mkdirs()
    val out = new PrintWriter(FileUtil.toFile(MyFileUtil.appendFileName(outputDirUri, "AppData.txt")))
    out.print(appData.toString)
    out.close()
    tar
  }
  
}