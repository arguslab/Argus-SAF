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

import org.argus.saf.cli.util.CliLogger
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.plugin.{TaintAnalysisApproach, TaintAnalysisModules, TaintAnalysisTask}
import org.argus.jawa.core.io.{FileReporter, MsgLevel, PrintReporter}
import org.argus.jawa.core.util.IgnoreException
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object TaintAnalysis{
//  private final val TITLE = "TaintAnalysis"
  def apply(module: TaintAnalysisModules.Value, debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean, guessPackage: Boolean, approach: TaintAnalysisApproach.Value): Unit = {
    val apkFileUris: MSet[FileResourceUri] = msetEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        apkFileUris ++= ApkFileUtil.getApks(FileUtil.toUri(dir))
      case file =>
        if(ApkGlobal.isValidApk(FileUtil.toUri(file)))
          apkFileUris += FileUtil.toUri(file)
        else println(file + " is not decompilable.")
    }
    taintAnalyze(module, apkFileUris.toSet, outputPath, debug, forceDelete, guessPackage, approach)
  }
  
  def taintAnalyze(module: TaintAnalysisModules.Value, apkFileUris: ISet[FileResourceUri], outputPath: String, debug: Boolean, forceDelete: Boolean, guessPackage: Boolean, approach: TaintAnalysisApproach.Value): Unit = {
    println("Total apks: " + apkFileUris.size)
    val outputUri = FileUtil.toUri(outputPath)
    try{
      var i: Int = 0
      apkFileUris.foreach{ fileUri =>
        i += 1
        try{
          println("Analyzing #" + i + ":" + fileUri)
          val reporter =
            if(debug) new FileReporter(getOutputDirUri(outputUri, fileUri), MsgLevel.INFO)
            else new PrintReporter(MsgLevel.ERROR)
          TaintAnalysisTask(module, Set((fileUri, outputUri)), forceDelete, reporter, guessPackage, approach).run
          println("Done!")
          if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
        } catch {
          case _: IgnoreException => println("No interesting element found for " + module)
          case e: Throwable =>
            CliLogger.logError(new File(outputPath), "Error: " , e)
        } finally {
          System.gc()
        }
      }
    } catch {
      case e: Throwable => 
        CliLogger.logError(new File(outputPath), "Error: " , e)
    }
  }
  
  private def getOutputDirUri(outputUri: FileResourceUri, apkUri: FileResourceUri): FileResourceUri = {
    outputUri + {if(!outputUri.endsWith("/")) "/" else ""} + apkUri.substring(apkUri.lastIndexOf("/") + 1, apkUri.lastIndexOf("."))
  }
}
