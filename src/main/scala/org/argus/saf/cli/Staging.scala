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

import akka.actor.{ActorSystem, _}
import akka.pattern.ask
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import org.argus.saf.cli.util.CliLogger
import org.argus.amandroid.concurrent.{AmandroidSupervisorActor, AnalysisSpec, PointsToAnalysisResult}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.sireum.util._

import scala.concurrent.ExecutionContext.Implicits._
import scala.concurrent.{Await, Future}
import scala.concurrent.duration._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object Staging {
  
//  private final val TITLE = "Staging"
  
  def apply(debug: Boolean, sourcePath: String, outputPath: String) {
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
    staging(apkFileUris.toSet, outputPath)
  }
  
  def staging(apkFileUris: ISet[FileResourceUri], outputPath: String) = {
    println("Total apks: " + apkFileUris.size)
    val outputUri = FileUtil.toUri(outputPath)
    val _system = ActorSystem("AmandroidTestApplication", ConfigFactory.load)
    implicit val to = Timeout(AndroidGlobalConfig.settings.timeout * apkFileUris.size.minutes)
    
    try {
      val supervisor = _system.actorOf(Props[AmandroidSupervisorActor], name = "AmandroidSupervisorActor")
      val futures = apkFileUris map {
        fileUri =>
          (supervisor ? AnalysisSpec(fileUri, outputUri, None, removeSupportGen = true, forceDelete = true)).mapTo[PointsToAnalysisResult]
      }
      val fseq = Future.sequence(futures)
      Await.result(fseq, Duration.Inf).foreach {
        dr =>
          println(dr)
      }
    } catch {
      case e: Throwable => 
        CliLogger.logError(new File(outputPath), "Error: " , e)
    } finally {
      _system.terminate()
    }
  }
}
