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
import org.argus.amandroid.core.decompile.ConverterUtil
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.{MsgLevel, PrintReporter}
import org.scalatest.{FlatSpec, Matchers}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class TaintWUBenchMarkTest extends FlatSpec with Matchers {
  private final val DEBUG = false

//  "ICC_Explicit_NoSrc_NoSink" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_nosink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "ICC_Explicit_NoSrc_Sink" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_sink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "ICC_Explicit_Src_NoSink" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_nosink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "ICC_Explicit_Src_Sink" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ICC_Implicit_NoSrc_NoSink" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_nosink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "ICC_Implicit_NoSrc_Sink" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_sink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "ICC_Implicit_Src_NoSink" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_nosink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ICC_Implicit_Src_Sink" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_sink.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_IntentService" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_intentservice.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ICC_Stateful" should "have 3 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccHandling/icc_stateful.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "ICC_DynRegister1" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_DynRegister2" should "have 3 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "ICC_Explicit1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_explicit1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ICC_Implicit1" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_action.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_Implicit2" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_category.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_Implicit3" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_Implicit4" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_Implicit5" should "have 3 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "ICC_Implicit6" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ICC_RPC_Comprehensive" should "have 3 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/Mixed/icc_rpc_comprehensive.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "RPC_LocalService" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/RpcHandling/rpc_localservice.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "RPC_MessengerService" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/RpcHandling/rpc_messengerservice.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "RPC_RemoteService" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/RpcHandling/rpc_remoteservice.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "RPC_ReturnSensitive" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/icc-bench/RpcHandling/rpc_returnsensitive.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }

//  "ActivityCommunication1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }

//  "ActivityCommunication2" should "have 3 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "ActivityCommunication3" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication3.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ActivityCommunication4" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication4.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ActivityCommunication5" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication5.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ActivityCommunication6" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication6.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ActivityCommunication7" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication7.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "ActivityCommunication8" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication8.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "BroadcastTaintAndLeak1" should "have 2 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/BroadcastTaintAndLeak1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ComponentNotInManifest1" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ComponentNotInManifest1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "EventOrdering1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/EventOrdering1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "IntentSink1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "IntentSink2" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "IntentSource1" should "have 2 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSource1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 2)
//  }
//
//  "ServiceCommunication1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/ServiceCommunication1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "SharedPreferences1" should "have 1 taint path" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/SharedPreferences1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "Singletons1" should "have 0 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/Singletons1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.isEmpty)
//  }
//
//  "UnresolvableIntent1" should "have 3 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/InterComponentCommunication/UnresolvableIntent1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 3)
//  }
//
//  "InterAppCommunication" should "have 19 taint paths" taggedAs Slow in {
//    val echoer_path = getClass.getResource("/droid-bench/InterAppCommunication/Echoer.apk").getPath
//    val sendsms_path = getClass.getResource("/droid-bench/InterAppCommunication/SendSMS.apk").getPath
//    val forresult_path = getClass.getResource("/droid-bench/InterAppCommunication/StartActivityForResult1.apk").getPath
//    val res = taintAnalysis(Set(echoer_path, sendsms_path, forresult_path))
//    assert(res.isDefined && res.get.getTaintedPaths.size == 19)
//  }
//
//  "AsyncTask1" should "have 1 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/Threading/AsyncTask1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "Executor1" should "have 1 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/Threading/Executor1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "JavaThread1" should "have 1 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/Threading/JavaThread1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "JavaThread2" should "have 1 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/Threading/JavaThread2.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }
//
//  "Looper1" should "have 1 taint paths" taggedAs Slow in {
//    val res = taintAnalysis(getClass.getResource("/droid-bench/Threading/Looper1.apk").getPath)
//    assert(res.isDefined && res.get.getTaintedPaths.size == 1)
//  }

  private def taintAnalysis(apkFile: String): Option[TaintAnalysisResult] = {
    taintAnalysis(Set(apkFile))
  }

  private def taintAnalysis(apkFiles: Set[String]): Option[TaintAnalysisResult] = {
    val fileUris = apkFiles.map(FileUtil.toUri)
    val outputUri = FileUtil.toUri(apkFiles.head.substring(0, apkFiles.head.length - 4))
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
    AndroidReachingFactsAnalysisConfig.resolve_static_init = true
    Context.init_context_length(0)
    val res = TaintAnalysisTask(TaintAnalysisModules.DATA_LEAKAGE, fileUris.map((_, outputUri)), forceDelete = true, reporter, guessPackage = true, TaintAnalysisApproach.BOTTOM_UP).run
    if(!DEBUG) {
      ConverterUtil.cleanDir(outputUri)
    }
    res
  }
}
