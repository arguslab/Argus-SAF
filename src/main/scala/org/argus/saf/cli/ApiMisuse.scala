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

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.plugin.apiMisuse.{CryptographicMisuse, HideIcon, SSLTLSMisuse}
import org.argus.amandroid.plugin.ApiMisuseModules
import org.argus.jawa.core.io.{FileReporter, MsgLevel, NoReporter}
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.suspark.InterProceduralSuperSpark
import org.argus.jawa.core.util.IgnoreException
import org.argus.saf.cli.util.CliLogger
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ApiMisuse {
  
//  private final val TITLE = "CryptoMisuse"
  
  def apply(module: ApiMisuseModules.Value, debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean, guessPackage: Boolean) {
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

    apiMisuse(apkFileUris.toSet, outputPath, module, debug, forceDelete, guessPackage)
  }
  
  def apiMisuse(apkFileUris: Set[FileResourceUri], outputPath: String, module: ApiMisuseModules.Value, debug: Boolean, forceDelete: Boolean, guessPackage: Boolean): Unit = {
    Context.init_context_length(AndroidGlobalConfig.settings.k_context)

    println("Total apks: " + apkFileUris.size)

    try{  
      var i: Int = 0
      apkFileUris.foreach{ fileUri =>
        i += 1
        try{
          println("Analyzing #" + i + ":" + fileUri)
          val reporter =
            if(debug) new FileReporter(getOutputDirUri(FileUtil.toUri(outputPath), fileUri), MsgLevel.INFO)
            else new NoReporter
          val yard = new ApkYard(reporter)
          val outputUri = FileUtil.toUri(outputPath)
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout)
          val settings = DecompilerSettings(debugMode = false, forceDelete = forceDelete, strategy, reporter)
          val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
          val (checker, buildIDFG) = module match {
            case ApiMisuseModules.CRYPTO_MISUSE => (new CryptographicMisuse, false)
            case ApiMisuseModules.HIDE_ICON =>
              val man = AppInfoCollector.analyzeManifest(reporter, FileUtil.appendFileName(apk.model.layout.outputSrcUri, "AndroidManifest.xml"))
              val mainComp = man.getIntentDB.getIntentFmap.find{ case (_, fs) =>
                  fs.exists{ f =>
                    f.getActions.contains("android.intent.action.MAIN") && f.getCategorys.contains("android.intent.category.LAUNCHER")
                  }
              }.map(_._1)
              if(mainComp.isEmpty) return
              (new HideIcon(mainComp.get), false)
            case ApiMisuseModules.SSLTLS_MISUSE => (new SSLTLSMisuse, false)
          }
          if(buildIDFG) {
            AppInfoCollector.collectInfo(apk, resolveCallBack = true, guessPackage)
            apk.model.getComponents foreach { comp =>
              val clazz = apk.getClassOrResolve(comp)
              val spark = new InterProceduralSuperSpark(apk)
              val idfg = spark.build(clazz.getDeclaredMethods.map(_.getSignature))
              val res = checker.check(apk, Some(idfg))
              println(res.toString)
            }
          } else {
            val res = checker.check(apk, None)
            println(res.toString)
          }
          if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
        } catch {
          case _: IgnoreException => println("No interested api found.")
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
