/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ApkYard(val reporter: Reporter) {
  private val apks: MMap[FileResourceUri, ApkGlobal] = mmapEmpty
  def addApk(apk: ApkGlobal): Unit = apks(apk.nameUri) = apk
  def removeApk(apk: ApkGlobal): Unit = apks -= apk.nameUri
  def removeApk(nameUri: FileResourceUri): Unit = apks -= nameUri
  def getApk(nameUri: FileResourceUri): Option[ApkGlobal] = apks.get(nameUri)
  def getApks: IMap[FileResourceUri, ApkGlobal] = this.apks.toMap

  /**
    * Load an apk or directly read decompiled apk dir.
    */
  def loadApk(apkUri: FileResourceUri, settings: DecompilerSettings, collectInfo: Boolean, resolveCallBack: Boolean, guessAppPackages: Boolean = false): ApkGlobal = {
    if(apkUri.endsWith(".apk")) {
      ApkDecompiler.decompile(apkUri, settings)
    }
    val apk = new ApkGlobal(ApkModel(apkUri, settings.strategy.layout), reporter)
    apk.load()
    if(collectInfo) {
      AppInfoCollector.collectInfo(apk, resolveCallBack, guessAppPackages)
    }
    addApk(apk)
    apk
  }
  

  private var interAppTaintResult: Option[Any] = None
  def setInterAppTaintAnalysisResult(tar: TaintAnalysisResult): Unit = this.synchronized(this.interAppTaintResult = Option(tar))
  def hasInterAppTaintAnalysisResult: Boolean = interAppTaintResult.isDefined
  def getInterAppTaintAnalysisResult: Option[TaintAnalysisResult] = this.interAppTaintResult.map(_.asInstanceOf[TaintAnalysisResult])
  
  def reset(): Unit = {
    this.apks.clear()
    this.interAppTaintResult = None
  }
}
