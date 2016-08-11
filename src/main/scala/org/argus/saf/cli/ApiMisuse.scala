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

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.argus.amandroid.plugin.apiMisuse.{CryptographicMisuse, HideIcon}
import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseModules}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.core.util.IgnoreException
import org.argus.jawa.core.{FileReporter, Global, MsgLevel, NoReporter}
import org.argus.saf.cli.util.CliLogger
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ApiMisuse {
  
//  private final val TITLE = "CryptoMisuse"
  
  def apply(module: ApiMisuseModules.Value, debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean) {
    val apkFileUris: MSet[FileResourceUri] = msetEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        apkFileUris ++= ApkFileUtil.getApks(FileUtil.toUri(dir), recursive = true)
      case file =>
        if(Apk.isValidApk(FileUtil.toUri(file)))
          apkFileUris += FileUtil.toUri(file)
        else println(file + " is not decompilable.")
    }
    val (checker, buildIDFG) = module match {
      case ApiMisuseModules.CRYPTO_MISUSE => (new CryptographicMisuse, true)
      case ApiMisuseModules.HIDE_ICON => (new HideIcon, false)
    }
    apiMisuse(apkFileUris.toSet, outputPath, checker, buildIDFG, debug, forceDelete)
  }
  
  def apiMisuse(apkFileUris: Set[FileResourceUri], outputPath: String, checker: ApiMisuseChecker, buildIDFG: Boolean, debug: Boolean, forceDelete: Boolean) = {
    Context.init_context_length(AndroidGlobalConfig.settings.k_context)
    AndroidReachingFactsAnalysisConfig.parallel = AndroidGlobalConfig.settings.parallel

    println("Total apks: " + apkFileUris.size)

    try{  
      var i: Int = 0
      apkFileUris.foreach{
        fileUri =>
          i += 1
          try{
            println("Analyzing #" + i + ":" + fileUri)
            val reporter = 
              if(debug) new FileReporter(getOutputDirUri(FileUtil.toUri(outputPath), fileUri), MsgLevel.INFO)
              else new NoReporter
            val global = new Global(fileUri, reporter)
            global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
            val yard = new ApkYard(global)
            val outputUri = FileUtil.toUri(outputPath)
            val apk = yard.loadApk(fileUri, outputUri, AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri), dexLog = false, debugMode = false, forceDelete)
            if(buildIDFG) {
              apk.getComponents foreach {
                comp =>
                  val clazz = global.getClassOrResolve(comp)
                  val idfg = InterproceduralSuperSpark(global, clazz.getDeclaredMethods.map(_.getSignature))
                  val res = checker.check(global, Some(idfg))
                  res.print()
              }
            } else {
              val res = checker.check(global, None)
              res.print()
            }
            if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
          } catch {
            case ie: IgnoreException => println("No interested api found.")
            case e: Throwable =>
              CliLogger.logError(new File(outputPath), "Error: " , e)
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
