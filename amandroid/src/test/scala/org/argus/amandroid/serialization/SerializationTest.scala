/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import java.io.{FileReader, FileWriter}

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.core.io.DefaultReporter
import org.json4s.{Formats, NoTypeHints}
import org.json4s.native.Serialization
import org.json4s.native.Serialization.{read, write}
import org.scalatest.{FlatSpec, Matchers}
import org.argus.jawa.core.util.FileUtil

/**
  * Created by fgwei on 3/23/17.
  */
class SerializationTest extends FlatSpec with Matchers {

//  "ApkModel" should "successfully serialized and deserialized" in {
//    val apkFile = getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath
//    val apkUri = FileUtil.toUri(apkFile)
//    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))
//    val reporter = new DefaultReporter
//    val yard = new ApkYard(reporter)
//    val layout = DecompileLayout(outputUri)
//    val strategy = DecompileStrategy(layout)
//    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
//    val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
//    val model = apk.model
//    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ApkModelSerializer
//    val apkRes = FileUtil.toFile(FileUtil.appendFileName(outputUri, "apk.json"))
//    val oapk = new FileWriter(apkRes)
//    try {
//      write(model, oapk)
//    } catch {
//      case e: Exception =>
//        e.printStackTrace()
//    } finally {
//      oapk.flush()
//      oapk.close()
//    }
//    val iapk = new FileReader(apkRes)
//    var newApkModel: ApkModel = null
//    try {
//      newApkModel = read[ApkModel](iapk)
//    } catch {
//      case e: Exception =>
//        e.printStackTrace()
//    } finally {
//      iapk.close()
//      ConverterUtil.cleanDir(outputUri)
//    }
//    require(
//      model.getAppName == newApkModel.getAppName &&
//      model.getComponents == newApkModel.getComponents &&
//      model.getLayoutControls == newApkModel.getLayoutControls &&
//      model.getCallbackMethods == newApkModel.getCallbackMethods &&
//      model.getComponentInfos == newApkModel.getComponentInfos &&
//      model.getEnvMap == newApkModel.getEnvMap)
//  }
}
