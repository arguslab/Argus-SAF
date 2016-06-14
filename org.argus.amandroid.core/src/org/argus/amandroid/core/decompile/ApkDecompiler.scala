/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
import org.argus.amandroid.core.dedex.PilarStyleCodeGeneratorListener
import org.argus.amandroid.core.parser.ManifestParser
import org.argus.jawa.core.JawaType
import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util._
import org.sireum.util.FileResourceUri

object ApkDecompiler {
  final val TITLE = "ApkDecompiler"
  final val DEBUG = false
  
  def decodeApk(apkUri: FileResourceUri, outputUri: FileResourceUri, forceDelete: Boolean, createFolder: Boolean = true): FileResourceUri = {
    AmDecoder.decode(apkUri, outputUri, forceDelete, createFolder)
  }
  
  def decompileDex(
      dexUri: FileResourceUri, 
      outUri: FileResourceUri, 
      dpsuri: Option[FileResourceUri], 
      pkg: String, 
      dexLog: Boolean, 
      debugMode: Boolean, 
      removeSupportGen: Boolean, 
      forceDelete: Boolean,
      listener: Option[PilarStyleCodeGeneratorListener] = None): (String, ISet[String]) = {
    val dependencies: MSet[String] = msetEmpty
    val recordFilter: (JawaType => Boolean) = {
      ot =>
        if(removeSupportGen) {
          if(ot.name.startsWith("android.support.v4")){
            dependencies += AndroidConstants.MAVEN_SUPPORT_V4
            false
          } else if (ot.name.startsWith("android.support.v13")) {
            dependencies += AndroidConstants.MAVEN_SUPPORT_V13
            false
          } else if (ot.name.startsWith("android.support.v7")){
            dependencies += AndroidConstants.MAVEN_APPCOMPAT
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
    val srcFolder: String = "src" + File.separator + {
      if(dexUri.startsWith(outUri)) dexUri.replace(outUri, "").replace(".dex", "").replace(".odex", "")
      else dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
    }.replaceAll("/", "_")
    val pilarOutUri = {
      val outPath = FileUtil.toFilePath(outUri)
      FileUtil.toUri(outPath + File.separator + srcFolder)
    }
    Dex2PilarConverter.convert(dexUri, pilarOutUri, outUri, dpsuri, recordFilter, dexLog, debugMode, forceDelete, listener)
    (srcFolder, dependencies.toSet)
  }
  
  def decompile(
      apk: File, 
      outputLocation: File, 
      dpsuri: Option[FileResourceUri], 
      dexLog: Boolean, 
      debugMode: Boolean, 
      removeSupportGen: Boolean, 
      forceDelete: Boolean,
      listener: Option[PilarStyleCodeGeneratorListener] = None,
      createFolder: Boolean = true): (FileResourceUri, ISet[String], ISet[String]) = {
    val outUri = decodeApk(FileUtil.toUri(apk), FileUtil.toUri(outputLocation), forceDelete, createFolder)
    val manifestUri = MyFileUtil.appendFileName(outUri, "AndroidManifest.xml")
    val pkg = ManifestParser.loadPackageName(manifestUri)
    val srcFolders: MSet[String] = msetEmpty
    val dependencies: MSet[String] = msetEmpty
    if(FileUtil.toFile(outUri).exists()) {
      val dexUris = FileUtil.listFiles(outUri, ".dex", recursive = true)
      dexUris.foreach {
        dexUri =>
          val (sf, dependent) = decompileDex(dexUri, outUri, dpsuri, pkg, dexLog, debugMode, removeSupportGen, forceDelete, listener)
          srcFolders += sf
          dependencies ++= dependent
      }
//      val apkUris = FileUtil.listFiles(outUri, ".apk", true)
//      apkUris.foreach {
//        apkUri =>
//          if(Apk.isValidApk(apkUri)) {
//            val apkFile = FileUtil.toFile(apkUri)
//            decompile(apkFile, apkFile.getParentFile, dpsuri, dexLog, debugMode, removeSupportGen, forceDelete, listener, createFolder)
//          }
//      }
    }
    (outUri, srcFolders.toSet, dependencies.toSet)
  }
}
