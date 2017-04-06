/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.concurrent

import akka.actor._
import akka.pattern.{AskTimeoutException, ask}
import com.typesafe.config.ConfigFactory
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.dedex.DecompileTimer
import org.argus.amandroid.core.{ApkGlobal, InvalidApk}
import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.concurrent.{Await, Future}
import scala.language.postfixOps

/**
 * This is an actor for managing the whole decompile process.
 *   
 * @author Fengguo Wei
 */
class DecompilerActor extends Actor with ActorLogging {
  
  def receive: Receive = {
    case ddata: DecompileData =>
      sender ! decompile(ddata)
  }
  
  def decompile(ddata: DecompileData): DecompilerResult = {
    log.info("Start decompile " + ddata.fileUri)
    if(ApkGlobal.isValidApk(ddata.fileUri)) {
        val listener = ddata.timeout match {
          case fd: FiniteDuration => Some(new DecompileTimer(fd))
          case _ => None
        }
        val apkFile = FileUtil.toFile(ddata.fileUri)
        val res = try {
          val layout = DecompileLayout(ddata.outputUri)
          val settings = DecompilerSettings(ddata.dpsuri, dexLog = false, debugMode = false, removeSupportGen = ddata.removeSupportGen, forceDelete = ddata.forceDelete, layout, listener)
          val (outApkUri, srcs, deps) = ApkDecompiler.decompile(ddata.fileUri, settings)
          DecompileSuccResult(ddata.fileUri, outApkUri, srcs, deps)
        } catch {
          case e: Throwable =>
            DecompileFailResult(ddata.fileUri, e)
        }
        res match {
          case _: DecompileFailResult =>
            val dirName = try{apkFile.getName.substring(0, apkFile.getName.lastIndexOf("."))} catch {case _: Exception => apkFile.getName}
            val outDir = FileUtil.toFile(MyFileUtil.appendFileName(ddata.outputUri, dirName))
            MyFileUtil.deleteDir(outDir)
          case _ =>
        }
        res
      } else {
        DecompileFailResult(ddata.fileUri, InvalidApk(ddata.fileUri))
      }
  }
}

object DecompileTestApplication extends App {
  val _system = ActorSystem("DecompileApp", ConfigFactory.load)
  val supervisor = _system.actorOf(Props[DecompilerActor], name = "decompile_supervisor")
  val fileUris = FileUtil.listFiles(FileUtil.toUri("/Users/fgwei/Develop/Sireum/apps/amandroid/sources/icc-bench"), ".apk", recursive = true)
  val outputUri = FileUtil.toUri("/Users/fgwei/Work/output/icc-bench")
  val futures = fileUris map {
    fileUri =>
      supervisor.ask(DecompileData(fileUri, outputUri, None, removeSupportGen = true, forceDelete = true, 10 seconds))(30 seconds).mapTo[DecompilerResult].recover{
          case _: AskTimeoutException =>
            (fileUri, false)
          case _: Exception =>
            (fileUri, false)
        }
  }
  val fseq = Future.sequence(futures)
  Await.result(fseq, Duration.Inf).foreach {
    dr => println(dr)
  }
  _system.terminate()
}
