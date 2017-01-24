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
  "AndroidSpecific_PrivateDataLeak3" should "have 1 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/AndroidSpecific/AndroidSpecific_PrivateDataLeak3.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

//  "FieldAndObjectSensitivity_FieldFlowSensitivity1" should "have 0 taint paths" in {
//    val res = taintAnalyze(getClass.getResource("/icc-bench/FieldAndObjectSensitivity/FieldAndObjectSensitivity_FieldFlowSensitivity1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }

  "ICC_Explicit_NoSrc_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Explicit_NoSrc_NoSink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_NoSrc_Sink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Explicit_NoSrc_Sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_Src_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Explicit_Src_NoSink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Explicit_Src_Sink" should "have 1 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Explicit_Src_Sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ICC_Implicit_NoSrc_NoSink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Implicit_NoSrc_NoSink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Implicit_NoSrc_Sink" should "have 0 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Implicit_NoSrc_Sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
  }

  "ICC_Implicit_Src_NoSink" should "have 1 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Implicit_Src_NoSink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "ICC_Implicit_Src_Sink" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccHandling/ICC_Implicit_Src_Sink.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "InterComponentCommunication_DynRegister1" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_DynRegister1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

//  "InterComponentCommunication_DynRegister2" should "have 2 taint paths" in {
//    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_DynRegister2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }

  "InterComponentCommunication_Explicit1" should "have 1 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Explicit1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
  }

  "InterComponentCommunication_Implicit1" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit1.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "InterComponentCommunication_Implicit2" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit2.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "InterComponentCommunication_Implicit3" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit3.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "InterComponentCommunication_Implicit4" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit4.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  "InterComponentCommunication_Implicit5" should "have 3 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit5.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
  }

  "InterComponentCommunication_Implicit6" should "have 2 taint paths" in {
    val res = taintAnalyze(getClass.getResource("/icc-bench/IccTargetFinding/InterComponentCommunication_Implicit6.apk").getPath)
    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
  }

  def taintAnalyze(apkFile: String): Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterproceduralDataDependenceAnalysis.Edge]] = {
    val fileUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))

    val reporter = new NoReporter
    val global = new Global(fileUri, reporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val res = TaintAnalysisTask(global, TaintAnalysisModules.DATA_LEAKAGE, fileUri, outputUri, None, forceDelete = true).run
    ConverterUtil.cleanDir(outputUri)
    res
  }
}
