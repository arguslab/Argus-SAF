/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.{MsgLevel, NoReporter, PrintReporter}
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 3/16/17.
  */
class AmandroidTest extends FlatSpec with Matchers {
  private final val DEBUG = false

  "icc_javatonative" should "have 2 components" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_javatonative.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 2)
  }

  "icc_nativetojava" should "have 2 components" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_nativetojava.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 2)
  }

  "native_complexdata" should "have 1 component" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/native_complexdata.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 1)
  }

  "native_leak" should "have 1 component" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/native_leak.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 1)
  }

  "native_noleak" should "have 1 component" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/native_noleak.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 1)
  }

  "native_pure" should "have 1 component" in {
    val res = loadApk(getClass.getResource("/NativeFlowBench/native_pure.apk").getPath)
    assert(res != null && res.model.getComponentInfos.size == 1)
  }

  private def loadApk(apkFile: String): ApkGlobal = {
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.appendFileName(FileUtil.toUri(FileUtil.toFile(apkUri).getParent), "output")
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new NoReporter
    var apk: ApkGlobal = null
    try {
      val yard = new ApkYard(reporter)
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
      apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      ConverterUtil.cleanDir(outputUri)
    }
    apk
  }
}
