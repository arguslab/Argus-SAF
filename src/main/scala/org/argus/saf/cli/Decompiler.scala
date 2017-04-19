/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli

import java.io.File

import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.saf.cli.util.CliLogger
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object Decompiler {
  def apply(debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean) {
    val outputUri = FileUtil.toUri(outputPath)
    try {
      val fileOrDir = new File(sourcePath)
      fileOrDir match {
        case dir if dir.isDirectory =>
          val decs = ApkFileUtil.getDecompileableFiles(FileUtil.toUri(dir))
          val dexs = FileUtil.listFiles(FileUtil.toUri(dir), ".dex", recursive = true)
          println(s"Processing directory which contains ${if(decs.nonEmpty) s"${decs.size} apk/jar${if(decs.size > 1) "s" else ""}" else ""} ${if(dexs.nonEmpty) s"${dexs.size} dex${if(dexs.size > 1) "s" else ""}" else ""}")
          var i = 0
          decs.foreach {
            apkUri =>
              i += 1
              println(i + ":####" + apkUri + "####")
              val layout = DecompileLayout(outputUri)
              val settings = DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = forceDelete, layout)
              try {
                ApkDecompiler.decompile(apkUri, settings)
                println("Done!")
              } catch {
                case e: Exception =>
                  println("Fail to decompile " + apkUri + " with error: " + e.getMessage)
                  CliLogger.logError(new File(outputPath), "Error: " , e)
              }
          }
          i = 0
          dexs.foreach {
            dexUri =>
              i += 1
              println(i + ":####" + dexUri + "####")
              val dexname = dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
              val layout = DecompileLayout(outputUri + "/" + dexname)
              val settings = DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = forceDelete, layout)
              try {
                ApkDecompiler.decompileDex("", dexUri, settings)
                println("Done!")
              } catch {
                case e: Exception =>
                  println("Fail to decompile " + dexUri + " with error: " + e.getMessage)
                  CliLogger.logError(new File(outputPath), "Error: " , e)
              }
          }
        case file =>
          println("Processing " + file)
          if(ApkGlobal.isValidApk(FileUtil.toUri(file))) {
            val layout = DecompileLayout(outputUri)
            val settings = DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = forceDelete, layout)
            ApkDecompiler.decompile(FileUtil.toUri(file), settings)
          } else if(file.getName.endsWith(".dex")) {
            val layout = DecompileLayout(outputUri)
            val settings = DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = forceDelete, layout)
            ApkDecompiler.decompileDex("", FileUtil.toUri(file), settings)
          } else println(file + " is not decompilable.")
      }
    } catch {
      case e: Exception => 
        CliLogger.logError(new File(outputPath), "Error: " , e)
    }
  }
}
