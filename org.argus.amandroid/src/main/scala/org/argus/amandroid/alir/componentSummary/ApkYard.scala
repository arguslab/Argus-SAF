/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import org.argus.jawa.core.util._

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.alir.{AlirEdge, InterProceduralNode}
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.Reporter

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
  
  def loadApk(apkUri: FileResourceUri, settings: DecompilerSettings, collectInfo: Boolean): ApkGlobal = {
    ApkDecompiler.decompile(apkUri, settings)
    val apk = new ApkGlobal(ApkModel(apkUri, settings.strategy.layout), reporter)
    apk.load()
    if(collectInfo) {
      AppInfoCollector.collectInfo(apk)
    }
    addApk(apk)
    apk
  }
  

  private var interAppTaintResult: Option[Any] = None
  def setInterAppTaintAnalysisResult[N <: InterProceduralNode, E <: AlirEdge[N]](tar: TaintAnalysisResult[N, E]): Unit = this.synchronized(this.interAppTaintResult = Option(tar))
  def hasInterAppTaintAnalysisResult: Boolean = interAppTaintResult.isDefined
  def getInterAppTaintAnalysisResult[N <: InterProceduralNode, E <: AlirEdge[N]]: Option[TaintAnalysisResult[N, E]] = this.interAppTaintResult.map(_.asInstanceOf[TaintAnalysisResult[N, E]])
  
  def reset(): Unit = {
    this.apks.clear()
    this.interAppTaintResult = None
  }
}
