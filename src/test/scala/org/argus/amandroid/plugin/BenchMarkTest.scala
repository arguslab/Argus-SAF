/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis
import org.argus.amandroid.core.decompile.ConverterUtil
import org.argus.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceAnalysis
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.{Global, NoReporter}
import org.scalatest.{FlatSpec, Matchers}
import org.sireum.util.FileUtil

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class BenchMarkTest extends FlatSpec with Matchers {
  "AndroidSpecific_PrivateDataLeak3" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/AndroidSpecific/AndroidSpecific_PrivateDataLeak3.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

//  "FieldAndObjectSensitivity_FieldFlowSensitivity1" should "have 0 taint paths" in {
//    val res = taintAnalyze(getClass.getResource("/icc-bench/FieldAndObjectSensitivity/FieldAndObjectSensitivity_FieldFlowSensitivity1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }

  "ICC_Explicit_NoSrc_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_nosink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_NoSrc_Sink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_Src_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_nosink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_Src_Sink" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ICC_Implicit_NoSrc_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_nosink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Implicit_NoSrc_Sink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Implicit_Src_NoSink" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_nosink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ICC_Implicit_Src_Sink" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_DynRegister1" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_DynRegister2" should "have 3 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
  }

  "ICC_Explicit1" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_explicit1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ICC_Implicit1" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_action.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_Implicit2" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_category.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_Implicit3" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_Implicit4" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ICC_Implicit5" should "have 3 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
  }

  "ICC_Implicit6" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ActivityCommunication1" should "have 1 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ActivityCommunication2" should "have 3 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
  }

  "ActivityCommunication3" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication3.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ActivityCommunication4" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication4.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ActivityCommunication5" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication5.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ActivityCommunication6" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication6.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ActivityCommunication7" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication7.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ActivityCommunication8" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication8.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "BroadcastTaintAndLeak1" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/BroadcastTaintAndLeak1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "ComponentNotInManifest1" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ComponentNotInManifest1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "EventOrdering1" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/EventOrdering1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "IntentSink1" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "IntentSink2" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "IntentSource1" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSource1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

//  "ServiceCommunication1" should "have 1 taint paths" in {
//    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/ServiceCommunication1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }

  "SharedPreferences1" should "have 1 taint path" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/SharedPreferences1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "Singletons1" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/Singletons1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "UnresolvableIntent1" should "have 3 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/droid-bench/InterComponentCommunication/UnresolvableIntent1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
  }

  def taintAnalyze(apkFile: String): Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterproceduralDataDependenceAnalysis.Edge]] = {
    val fileUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))

    val reporter = new NoReporter
    val global = new Global(fileUri, reporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    AndroidReachingFactsAnalysisConfig.resolve_static_init = true
    val res = TaintAnalysisTask(global, TaintAnalysisModules.DATA_LEAKAGE, fileUri, outputUri, None, forceDelete = true).run
    ConverterUtil.cleanDir(outputUri)
    res
  }
}
