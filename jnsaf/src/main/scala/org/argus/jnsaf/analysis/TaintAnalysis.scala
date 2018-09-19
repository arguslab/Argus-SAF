/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.analysis

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.jawa.core.util._
import org.argus.jawa.core._
import org.argus.jawa.flow.summary.store.TaintStore
import TimeUtil
import org.argus.jnsaf.client.NativeDroidClient
import org.argus.jnsaf.taint.JNTaintAnalysis

import scala.language.postfixOps

/**
  * Created by fgwei on 3/19/17.
  */
object TaintAnalysis {
  def apply(apkFile: String, output: String, debug: Boolean, guessPackage: Boolean): IMap[JawaType, TaintStore] = {
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(output)
    val outReportUri = ApkFileUtil.getOutputUri(apkUri, outputUri)
    val reporter = if(debug) {
      new FileReporter(outReportUri, MsgLevel.INFO)
    } else {
      new PrintReporter(MsgLevel.ERROR)
    }
    TimeUtil.timed("TaintAnalysis Running Time", reporter) {
      build(apkUri, outputUri, reporter, guessPackage)
    }
  }

  private def build(apkUri: FileResourceUri, outputUri: FileResourceUri, reporter: Reporter, guessPackage: Boolean): IMap[JawaType, TaintStore] = {

    val client = new NativeDroidClient("localhost", 50051, reporter)

    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = false, guessPackage)

    try {
      val handler = new NativeMethodHandler(client)
      val jntaint = new JNTaintAnalysis(apk, handler, reporter)
      jntaint.process
    } catch {
      case e: Throwable =>
        e.printStackTrace()
        imapEmpty
    } finally {
//      bridge.close()
    }
  }
}
