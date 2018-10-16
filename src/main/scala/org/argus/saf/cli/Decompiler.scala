/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli

import java.io.File

import org.argus.amandroid.core.decompile._
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.io.{DefaultReporter, MsgLevel, PrintReporter}
import org.argus.saf.cli.util.CliLogger
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object Decompiler {
  def apply(debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean, srcLevel: DecompileLevel.Value, libLevel: DecompileLevel.Value) {
    val outputUri = FileUtil.toUri(outputPath)
    val reporter = if(debug) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
    try {
      val fileOrDir = new File(sourcePath)
      fileOrDir match {
        case dir if dir.isDirectory =>
          val decs = ApkFileUtil.getDecompileableFiles(FileUtil.toUri(dir))
          val dexs = FileUtil.listFiles(FileUtil.toUri(dir), ".dex", recursive = true)
          reporter.println(s"Processing directory which contains ${if(decs.nonEmpty) s"${decs.size} apk/jar${if(decs.size > 1) "s" else ""}" else ""} ${if(dexs.nonEmpty) s"${dexs.size} dex${if(dexs.size > 1) "s" else ""}" else ""}")
          var i = 0
          decs.foreach { apkUri =>
            i += 1
            reporter.println(i + ":####" + apkUri + "####")
            val layout = DecompileLayout(outputUri)
            val strategy = DecompileStrategy(layout, sourceLevel = srcLevel, thirdPartyLibLevel = libLevel)
            val settings = DecompilerSettings(debugMode = debug, forceDelete = forceDelete, strategy, reporter)
            try {
              ApkDecompiler.decompile(apkUri, settings)
              reporter.println("Done!")
            } catch {
              case e: Exception =>
                println("Fail to decompile " + apkUri + " with error: " + e.getMessage)
                CliLogger.logError(new File(outputPath), "Error: " , e)
            }
          }
          i = 0
          dexs.foreach { dexUri =>
            i += 1
            println(i + ":####" + dexUri + "####")
            val dexname = dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
            val layout = DecompileLayout(outputUri + "/" + dexname)
            val strategy = DecompileStrategy(layout, sourceLevel = srcLevel, thirdPartyLibLevel = libLevel)
            val settings = DecompilerSettings(debugMode = debug, forceDelete = forceDelete, strategy, new DefaultReporter)
            try {
              Dex2JawaConverter.convert(dexUri, settings)
              reporter.println("Done!")
            } catch {
              case e: Exception =>
                reporter.println("Fail to decompile " + dexUri + " with error: " + e.getMessage)
                CliLogger.logError(new File(outputPath), "Error: " , e)
            }
          }
        case file =>
          reporter.println("Processing " + file)
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout, sourceLevel = srcLevel, thirdPartyLibLevel = libLevel)
          val settings = DecompilerSettings(debugMode = debug, forceDelete = forceDelete, strategy, reporter)
          if(ApkGlobal.isValidApk(FileUtil.toUri(file))) {
            ApkDecompiler.decompile(FileUtil.toUri(file), settings)
          } else if(file.getName.endsWith(".dex")) {
            Dex2JawaConverter.convert(FileUtil.toUri(file), settings)
          } else reporter.println(file + " is not decompilable.")
      }
    } catch {
      case e: Exception => 
        CliLogger.logError(new File(outputPath), "Error: " , e)
    }
  }
}
