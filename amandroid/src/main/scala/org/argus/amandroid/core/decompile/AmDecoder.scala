/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.decompile

import java.io.File

import org.argus.jawa.core.util._
import java.util.logging.Logger
import java.util.logging.LogManager

import brut.androlib.ApkDecoder
import brut.androlib.err.CantFindFrameworkResException
import org.argus.amandroid.core.util.ApkFileUtil

object AmDecoder {
  final private val TITLE = "AmDecoder"
  /**
   *  Decode apk file and return outputpath
   *  @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
   */
  def decode(sourcePathUri: FileResourceUri, outputUri: FileResourceUri, forceDelete: Boolean = true, createFolder: Boolean = true, srcFolder: String): FileResourceUri = {
    // make it as quiet mode
    val logger = Logger.getLogger("")
    logger.getHandlers.foreach { h =>
      logger.removeHandler(h)
    }
    LogManager.getLogManager.reset()

    val apkFile = FileUtil.toFile(sourcePathUri)
    val outputDir = 
      if(createFolder) FileUtil.toFile(ApkFileUtil.getOutputUri(sourcePathUri, outputUri))
      else FileUtil.toFile(outputUri)
    if(new File(outputDir, srcFolder).exists() && !forceDelete) return FileUtil.toUri(outputDir)
    try {
      val decoder = new ApkDecoder
      decoder.setDecodeSources(0x0000) // DECODE_SOURCES_NONE = 0x0000
      decoder.setApkFile(apkFile)
      decoder.setOutDir(outputDir)
      decoder.setForceDelete(true)
      decoder.decode()
    } catch {
      case ie: InterruptedException => throw ie
      case fe: CantFindFrameworkResException =>
        System.err.println(TITLE + ": Can't find framework resources for package of id: " + fe.getPkgId + ". You must install proper framework files, see apk-tool website for more info.")
      case e: Exception =>
        System.err.println(TITLE + ": " + e.getMessage + ". See apk-tool website for more info.")
    }
    FileUtil.toUri(outputDir)
  }
}
