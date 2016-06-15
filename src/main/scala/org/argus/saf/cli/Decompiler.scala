/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli

import java.io.File

import org.argus.amandroid.core.decompile.ApkDecompiler
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.argus.saf.cli.util.CliLogger
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object Decompiler {
  def apply(debug: Boolean, sourcePath: String, outputPath: String) {
    val dpsuri = AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri)
    val outputUri = FileUtil.toUri(outputPath)
    try {
      val fileOrDir = new File(sourcePath)
      fileOrDir match {
        case dir if dir.isDirectory =>
          val decs = ApkFileUtil.getDecompileableFiles(FileUtil.toUri(dir), recursive = true)
          val dexs = FileUtil.listFiles(FileUtil.toUri(dir), ".dex", recursive = true)
          println(s"Processing directory which contains ${if(decs.nonEmpty) s"${decs.size} apk/jar${if(decs.size > 1) "s" else ""}" else ""} ${if(dexs.nonEmpty) s"${dexs.size} dex${if(dexs.size > 1) "s" else ""}" else ""}")
          decs.foreach {
            apkUri =>
              println("####" + apkUri + "####")
              ApkDecompiler.decompile(FileUtil.toFile(apkUri), FileUtil.toFile(outputUri), dpsuri, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = true)
              println("Done!")
          }
          dexs.foreach {
            dexUri =>
              println("####" + dexUri + "####")
              val dexname = dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
              ApkDecompiler.decompileDex(dexUri, outputUri + "/" + dexname, dpsuri, "", dexLog = false, debugMode = false, removeSupportGen = false, forceDelete = true)
              println("Done!")
          }
        case file =>
          println("Processing " + file)
          if(Apk.isValidApk(FileUtil.toUri(file)))
            ApkDecompiler.decompile(file, FileUtil.toFile(outputUri), dpsuri, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = true)
          else if(file.getName.endsWith(".dex")) ApkDecompiler.decompileDex(FileUtil.toUri(file), outputUri, dpsuri, "", dexLog = false, debugMode = false, removeSupportGen = false, forceDelete = true)
          else println(file + " is not decompilable.")
      }
    } catch {
      case e: Exception => 
        CliLogger.logError(new File(outputPath), "Error: " , e)
    }
  }
}
