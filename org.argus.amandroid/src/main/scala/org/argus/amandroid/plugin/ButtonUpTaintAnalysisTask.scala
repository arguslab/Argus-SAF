/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.taintAnalysis.DataLeakageAndroidSourceAndSinkManager
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.plugin.TaintAnalysisModules._
import org.argus.amandroid.plugin.communication.CommunicationSourceAndSinkManager
import org.argus.amandroid.plugin.dataInjection.IntentInjectionSourceAndSinkManager
import org.argus.amandroid.plugin.oauth.OAuthSourceAndSinkManager
import org.argus.amandroid.plugin.password.PasswordSourceAndSinkManager
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.Reporter
import org.argus.jawa.core.util.{FileResourceUri, ISet}

class ButtonUpTaintAnalysisTask(module: TaintAnalysisModules.Value, fileUris: ISet[(FileResourceUri, FileResourceUri)], forceDelete: Boolean, reporter: Reporter) {
  def run: Option[TaintAnalysisResult] = {
    val yard = new ApkYard(reporter)
    val apks = fileUris.map{ case (apkUri, outputUri) =>
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = forceDelete, strategy, reporter)
      yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
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
  }
}
