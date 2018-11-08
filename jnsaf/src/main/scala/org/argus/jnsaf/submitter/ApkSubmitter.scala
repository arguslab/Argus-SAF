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
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util.{FileResourceUri, FileUtil}
import org.argus.jnsaf.client.JNSafClient

object ApkSubmitter {
  def apply(sourcePath: String, address: String, port: Int): Unit = {
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        submitApkInDir(FileUtil.toUri(dir), address, port)
      case file =>
        if(ApkGlobal.isValidApk(FileUtil.toUri(file)))
          submitApk(FileUtil.toUri(file), address, port)
        else println(file + " is not decompilable.")
    }
  }
  def submitApkInDir(dirUri: FileResourceUri, address: String, port: Int): Unit = {
    FileUtil.listFiles(dirUri, ".apk", recursive = true) foreach { apkUri =>
      submitApk(apkUri, address, port)
    }
  }
  def submitApk(apkUri: FileResourceUri, address: String, port: Int): Unit = {
    val reporter = new PrintReporter(MsgLevel.INFO)
    val client = new JNSafClient(address, port, reporter)
    client.taintAnalysis(apkUri)
  }
}
