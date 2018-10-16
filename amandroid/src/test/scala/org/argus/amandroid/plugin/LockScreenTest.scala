/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.plugin.lockScreen.LockScreen
import org.argus.jawa.core.io.{MsgLevel, NoReporter, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.FlatSpec

class LockScreenTest extends FlatSpec{
  private final val DEBUG=false

  "LockScreen" should "be Flagged True" in {
    val result:Boolean=testLockScreen(getClass.getResource("/apks/lockScreen.apk").getPath)
    assert(result)
  }

  "Crypto" should "be Flagged No" in {
    val result:Boolean=testLockScreen(getClass.getResource("/apks/crypto.apk").getPath)
    assert(!result)
  }

  "bgsuFun" should "be Flagged Yes" in {
    val result:Boolean=testLockScreen(getClass.getResource("/apks/bgsuFun.apk").getPath)
    assert(result)
  }

  private def testLockScreen(apkFile:String): Boolean =
  {
    val fileUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))
    val reporter =
      if(DEBUG) new PrintReporter(MsgLevel.INFO)
      else new NoReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)

    val checker=new LockScreen()
    val res=checker.checkLockScreen(apk,None)
    res
  }
}
