package org.argus.amandroid.plugin

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.plugin.dynamicLoading.DynamicLoading
import org.argus.jawa.core.{MsgLevel, NoReporter, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.FlatSpec


class DynamicLoadingTest extends FlatSpec{
  private final val DEBUG=false

  /*"Bankbot" should "be flagged yes" in {
    val result:Boolean=testDynamicLoading(getClass.getResource("/apks/bankbot.apk").getPath)
  }
  */

  "dynamicLoader" should "be flagged yes" in {
    val result:Boolean=testDynamicLoading(getClass.getResource("/apks/dynamicLoader.apk").getPath)
  }

  /*
  "Hijack" should "be flagged yes" in {
    val result:Boolean=testDynamicLoading(getClass.getResource("/apks/Hijack.apk").getPath)
  }

  "LockScreen" should "be flagged No" in {
    val result:Boolean=testDynamicLoading(getClass.getResource("/apks/lockScreen.apk").getPath)
  }
  */

  private def testDynamicLoading(apkFile:String):Boolean=
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

    val checker=new DynamicLoading()
    val res=checker.checkDynamicLoading(apk,None)
    res
  }


}
