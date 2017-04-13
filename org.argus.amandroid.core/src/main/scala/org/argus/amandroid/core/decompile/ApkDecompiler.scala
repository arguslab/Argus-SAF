/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.decompile

import java.io.File

import org.argus.amandroid.core.AndroidConstants
import org.argus.amandroid.core.parser.ManifestParser
import org.argus.jawa.core.JawaType
import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util._
import org.sireum.util.FileResourceUri

object ApkDecompiler {
  final val TITLE = "ApkDecompiler"
  final val DEBUG = false
  
  def decodeApk(apkUri: FileResourceUri, outputUri: FileResourceUri, forceDelete: Boolean, createFolder: Boolean = true, srcFolder: String): FileResourceUri = {
    AmDecoder.decode(apkUri, outputUri, forceDelete, createFolder, srcFolder)
  }
  
  def decompileDex(pkg: String, dexUri: FileResourceUri, settings: DecompilerSettings): (String, ISet[String]) = {
    val dependencies: MSet[String] = msetEmpty
    val recordFilter: (JawaType => Boolean) = {
      ot =>
        if(settings.removeSupportGen) {
          if(ot.name.startsWith("android.support.v4")){
            dependencies += AndroidConstants.MAVEN_SUPPORT_V4
            false
          } else if (ot.name.startsWith("android.support.v13")) {
            dependencies += AndroidConstants.MAVEN_SUPPORT_V13
            false
          } else if (ot.name.startsWith("android.support.v7")){
            dependencies += AndroidConstants.MAVEN_APPCOMPAT
            false
          } else if (ot.name.startsWith("android.support.design")) {
            dependencies += AndroidConstants.MAVEN_DESIGN
            false
          } else if (ot.name.startsWith("android.support.annotation")) {
            dependencies += AndroidConstants.MAVEN_SUPPORT_ANNOTATIONS
            false
          } else if (ot.name.startsWith("android.support.constraint")) {
            dependencies += AndroidConstants.MAVEN_CONSTRAINT_LAYOUT
            false
          } else if(ot.name.endsWith(pkg + ".BuildConfig") ||
              ot.name.endsWith(pkg + ".Manifest") ||
              ot.name.contains(pkg + ".Manifest$") ||
              ot.name.endsWith(pkg + ".R") ||
              ot.name.contains(pkg + ".R$")) {
            false
          } else true
        } else true
    }
    val srcFolder: String = settings.layout.sourceFolder(dexUri)
    val jawaOutUri = {
      val outPath = FileUtil.toFilePath(settings.layout.outputSrcUri)
      FileUtil.toUri(outPath + File.separator + srcFolder)
    }
    Dex2PilarConverter.convert(dexUri, jawaOutUri, recordFilter, settings)
    (srcFolder, dependencies.toSet)
  }
  
  def decompile(apkUri: FileResourceUri, settings: DecompilerSettings): (FileResourceUri, ISet[String], ISet[String]) = {
    val outUri = decodeApk(apkUri, settings.layout.outputUri, settings.forceDelete, settings.layout.createFolder, settings.layout.srcFolder)
    settings.layout.outputSrcUri = outUri
    val manifestUri = MyFileUtil.appendFileName(outUri, "AndroidManifest.xml")
    val pkg = ManifestParser.loadPackageName(manifestUri)
    val srcFolders: MSet[String] = msetEmpty
    val dependencies: MSet[String] = msetEmpty
    if(FileUtil.toFile(outUri).exists()) {
      val dexUris = FileUtil.listFiles(outUri, ".dex", recursive = true) ++ FileUtil.listFiles(outUri, ".odex", recursive = true)
      dexUris.foreach {
        dexUri =>
          val (sf, dependent) = decompileDex(pkg, dexUri, settings)
          srcFolders += sf
          dependencies ++= dependent
      }
    }
    (outUri, srcFolders.toSet, dependencies.toSet)
  }
}