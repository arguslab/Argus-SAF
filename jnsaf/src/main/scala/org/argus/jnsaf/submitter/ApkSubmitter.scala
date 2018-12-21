/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.submitter

import java.io.File

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.plugin.TaintAnalysisApproach
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.taint_result.TaintResult
import org.argus.jnsaf.client.JNSafClient

object ApkSubmitter {
  def apply(sourcePath: String, address: String, port: Int, approach: TaintAnalysisApproach.Value): IMap[String, Option[TaintResult]] = {
    val analysisResult: MMap[String, Option[TaintResult]] = mmapEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        submitApkInDir(FileUtil.toUri(dir), address, port, approach, analysisResult)
      case file =>
        if(ApkGlobal.isValidApk(FileUtil.toUri(file)))
          submitApk(FileUtil.toUri(file), address, port, approach, analysisResult)
        else println(file + " is not decompilable.")
    }
    analysisResult.toMap
  }
  def submitApkInDir(dirUri: FileResourceUri, address: String, port: Int, approach: TaintAnalysisApproach.Value, result: MMap[String, Option[TaintResult]]): Unit = {
    FileUtil.listFiles(dirUri, ".apk", recursive = true) foreach { apkUri =>
      submitApk(apkUri, address, port, approach, result)
    }
  }
  def submitApk(apkUri: FileResourceUri, address: String, port: Int, approach: TaintAnalysisApproach.Value, result: MMap[String, Option[TaintResult]]): Unit = {
    val reporter = new PrintReporter(MsgLevel.INFO)
    val client = new JNSafClient(address, port, reporter)
    val apk = FileUtil.toFile(apkUri)
    result(apk.getName) = client.taintAnalysis(apkUri, approach)
  }
}
