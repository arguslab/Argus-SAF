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

import org.argus.amandroid.core.parser.ManifestParser
import org.argus.jawa.core.util._

object ApkDecompiler {
  final val TITLE = "ApkDecompiler"
  final val DEBUG = false
  
  def decodeApk(apkUri: FileResourceUri, outputUri: FileResourceUri, forceDelete: Boolean, createFolder: Boolean = true, srcFolder: String): FileResourceUri = {
    AmDecoder.decode(apkUri, outputUri, forceDelete, createFolder, srcFolder)
  }
  
  def decompile(apkUri: FileResourceUri, settings: DecompilerSettings): Unit = {
    val outApkUri = decodeApk(apkUri, settings.strategy.layout.outputUri, settings.forceDelete, settings.strategy.layout.createFolder, settings.strategy.layout.srcFolder)
    settings.strategy.layout.outputSrcUri = outApkUri
    val manifestUri = FileUtil.appendFileName(outApkUri, "AndroidManifest.xml")
    val pkg = ManifestParser.loadPackageName(manifestUri)
    settings.strategy.layout.pkg = pkg
    if(FileUtil.toFile(outApkUri).exists()) {
      val dexUris = FileUtil.listFiles(outApkUri, ".dex", recursive = true) ++ FileUtil.listFiles(outApkUri, ".odex", recursive = true)
      dexUris.foreach { dexUri =>
        Dex2JawaConverter.convert(dexUri, settings)
      }
    }
  }
}