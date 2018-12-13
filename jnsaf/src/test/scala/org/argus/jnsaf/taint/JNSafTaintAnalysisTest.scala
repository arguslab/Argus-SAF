/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.taint

import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.io.{MsgLevel, NoReporter, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jnsaf.analysis.{JNISourceAndSinkManager, NativeMethodHandler}
import org.argus.jnsaf.client.NativeDroidClient
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 1/28/18.
  */
class JNSafTaintAnalysisTest extends FlatSpec with Matchers {
  private final val DEBUG = false

//  "icc_javatonative" should "have 2 components" in {
//    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_javatonative.apk").getPath)
//    assert(res != null && res.model.getComponentInfos.size == 2)
//  }
//
//  "icc_nativetojava" should "have 2 components" in {
//    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_nativetojava.apk").getPath)
//    assert(res != null && res.model.getComponentInfos.size == 2)
//  }
//
//  "native_complexdata" should "have leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_complexdata.apk").getPath,
//      getClass.getResource("/expected/native_complexdata/native_complexdata.safsu").getPath,
//      getClass.getResource("/expected/native_complexdata/native_complexdata.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//}
//
//  "native_heap_modify" should "have leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_heap_modify.apk").getPath,
//      getClass.getResource("/expected/native_heap_modify/native_heap_modify.safsu").getPath,
//      getClass.getResource("/expected/native_heap_modify/native_heap_modify.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//  }
//
//  "native_leak" should "have leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_leak.apk").getPath,
//      getClass.getResource("/expected/native_leak/native_leak.safsu").getPath,
//      getClass.getResource("/expected/native_leak/native_leak.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//  }
//
//  "native_noleak" should "have no leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_noleak.apk").getPath,
//      getClass.getResource("/expected/native_noleak/native_noleak.safsu").getPath,
//      getClass.getResource("/expected/native_noleak/native_noleak.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//  }
////
////  "native_pure" should "have 1 component" in {
////    val res = loadApk(getClass.getResource("/NativeFlowBench/native_pure.apk").getPath)
////    assert(res != null && res.model.getComponentInfos.size == 1)
////  }
//
//  "native_source" should "have leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_source.apk").getPath,
//      getClass.getResource("/expected/native_source/native_source.safsu").getPath,
//      getClass.getResource("/expected/native_source/native_source.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//  }
//
//  "native_method_overloading" should "have leak" in {
//    val result = analyze(
//      getClass.getResource("/NativeFlowBench/native_method_overloading.apk").getPath,
//      getClass.getResource("/expected/native_method_overloading/native_method_overloading.safsu").getPath,
//      getClass.getResource("/expected/native_method_overloading/native_method_overloading.txt").getPath)
//    assert(result.getTaintedPaths.nonEmpty)
//  }

  private def analyze(apkFile: String, safsuFile: String, sasFile: String): TaintAnalysisResult = {
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.appendFileName(FileUtil.toUri(FileUtil.toFile(apkUri).getParent), "output")
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new NoReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
    val handler = new NativeMethodHandler(new NativeDroidClient("localhost", 50051, "", reporter))
    val ssm: AndroidSourceAndSinkManager = new JNISourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
    val provider = new AndroidSummaryProvider(apk)
    val cba = new ComponentBasedAnalysis(yard)
    val jntaint = new JNTaintAnalysis(yard, apk, handler, ssm, provider, cba, reporter, 3)
    val safsuFileUri = FileUtil.toUri(safsuFile)
    val name = FileUtil.filename(safsuFileUri)
    provider.sm.registerExternalFile(safsuFileUri, name, fileAndSubsigMatch = false)
    ssm.parseFile(sasFile)
    val res = jntaint.process
    ConverterUtil.cleanDir(outputUri)
    res
  }
}
