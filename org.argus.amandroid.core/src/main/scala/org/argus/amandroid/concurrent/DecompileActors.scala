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
import org.argus.amandroid.core.decompile.{ApkDecompiler, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.{ApkGlobal, InvalidApk}
import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util._

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
        val listener = None
        val apkFile = FileUtil.toFile(ddata.fileUri)
        val res = try {
          val layout = DecompileLayout(ddata.outputUri)
          val settings = DecompilerSettings(debugMode = false, removeSupportGen = ddata.removeSupportGen, forceDelete = ddata.forceDelete, layout, listener)
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