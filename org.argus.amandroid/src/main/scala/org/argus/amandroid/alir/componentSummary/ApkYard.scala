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
import java.io.File

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.jawa.alir.{AlirEdge, InterProceduralNode}
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.{Constants, Reporter}

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
    val (outUri, srcs, _) = ApkDecompiler.decompile(apkUri, settings)
    val apk = new ApkGlobal(ApkModel(apkUri, outUri, srcs), reporter)
    srcs foreach {
      src =>
        val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
        if(FileUtil.toFile(fileUri).exists()) {
          //store the app's jawa code in AmandroidCodeSource which is organized class by class.
          apk.load(fileUri, Constants.JAWA_FILE_EXT, AndroidLibraryAPISummary)
        }
    }
    if(collectInfo)
      AppInfoCollector.collectInfo(apk)
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
