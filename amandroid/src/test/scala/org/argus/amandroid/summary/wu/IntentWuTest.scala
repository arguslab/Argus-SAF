/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.wu

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.model.Intent
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTASlot
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core.util._
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jawa.summary.wu.{PTStore, PTSummary, WorkUnit}
import org.scalatest.tagobjects.Slow
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class IntentWuTest extends FlatSpec with Matchers {
  final val DEBUG = false

  trait MyTest {
    def ep(sigStr: String): MyTest
    def produce(intentStr: String): Unit
  }

  implicit def file(file: String): MyTest = {
    if(file.endsWith(".apk")) {
      new TestApk(file)
    } else {
      new TestFile(file)
    }
  }

  "/jawa/intent/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.singleFunc:()V" produce """
    |Intent:
    |  Component Names:
    |    org.arguslab.icc_explicit1.FooActivity
    |  Explicit: true
    |  Precise: true
  """.stripMargin.trim

  "/jawa/intent/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.caller:()V" produce """
    |Intent:
    |  Component Names:
    |    org.arguslab.icc_explicit1.FooActivity
    |  Explicit: true
    |  Precise: true
  """.stripMargin.trim

  "/jawa/intent/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.caller2:()V" produce """
    |Intent:
    |  Component Names:
    |    org.arguslab.icc_explicit1.FooActivity
    |  Explicit: true
    |  Precise: true
  """.stripMargin.trim

  class TestFile(file: String) extends MyTest {
    var entrypoint: Signature = _

    val handler: AndroidModelCallHandler = new AndroidModelCallHandler

    def ep(sigStr: String): MyTest = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(intentStr: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath))
        val sm: SummaryManager = new AndroidSummaryProvider(global).getSummaryManager
        val cg = SignatureBasedCallGraph(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator[Global](global, sm, handler,
          PTSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val store: PTStore = new PTStore
        val orderedWUs: IList[WorkUnit[Global]] = cg.topologicalSort(true).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new IntentWu(global, method, sm, handler, store, "intent")
        }
        analysis.build(orderedWUs)
        val candidate = store.getPropertyOrElse[MSet[(Context, PTASlot)]]("intent", msetEmpty)
        var intent: Option[Intent] = None
        candidate.foreach { case (ctx, s) =>
          val intentInss = store.resolved.pointsToSet(ctx, s)
          intent = IntentHelper.getIntentContents(store.resolved, intentInss, ctx).headOption
        }
        assert(intent.isDefined && intent.get.toString == intentStr)
      }
    }
  }

  "/icc-bench/IccTargetFinding/icc_dynregister1.apk" produce
    """
      |Intent:
      |  Actions:
      |    com.fgwei
      |  Explicit: false
      |  Precise: true
    """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_dynregister2.apk" produce """
    |Intent:
    |  Explicit: false
    |  Precise: false
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_explicit1.apk" produce """
    |Intent:
    |  Component Names:
    |    org.arguslab.icc_explicit1.FooActivity
    |  Explicit: true
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_action.apk" produce """
    |Intent:
    |  Actions:
    |    amandroid.impliciticctest_action.testaction
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_category.apk" produce """
    |Intent:
    |  Actions:
    |    test
    |  Categories:
    |    amandroid.impliciticctest_Categories.testcategory1
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_data1.apk" produce """
    |Intent:
    |  Data:
    |    schemes= amandroid host= fgwei port= 4444 path= null pathPrefix= null pathPattern= null
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_data2.apk" produce """
    |Intent:
    |  Types:
    |    test/type
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_mix1.apk" produce """
    |Intent:
    |  Actions:
    |    test_action
    |  Categories:
    |    test_category1
    |    test_category2
    |  Data:
    |    schemes= amandroid host= fgwei port= 8888 path= /abc/def pathPrefix= null pathPattern= null
    |  Types:
    |    test/type
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  "/icc-bench/IccTargetFinding/icc_implicit_mix2.apk" produce """
    |Intent:
    |  Actions:
    |    test_action
    |  Categories:
    |    test_category1
    |    test_category2
    |  Data:
    |    schemes= amandroid host= fgwei port= 8888 path= /abc/def pathPrefix= null pathPattern= null
    |  Types:
    |    test/type
    |  Explicit: false
    |  Precise: true
  """.stripMargin.trim

  class TestApk(file: String) extends MyTest {

    val handler: AndroidModelCallHandler = new AndroidModelCallHandler

    def ep(sigStr: String): MyTest = {
      this
    }

    def produce(intentStr: String): Unit = {
      file should s"produce expected summary" taggedAs Slow in {
        val apkFile = getClass.getResource(file).getPath
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)

        val fileUri = FileUtil.toUri(apkFile)
        val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))
        val yard = new ApkYard(reporter)
        val layout = DecompileLayout(outputUri)
        val strategy = DecompileStrategy(layout)
        val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
        val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)
        val sm: SummaryManager = new AndroidSummaryProvider(apk).getSummaryManager
        val analysis = new BottomUpSummaryGenerator[Global](apk, sm, handler,
          PTSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val store: PTStore = new PTStore

        val (_, (sig, _)) = apk.model.getEnvMap.find{ case (comp, _) =>
          comp.toString.endsWith(".MainActivity")
        }.get
        val cg = SignatureBasedCallGraph(apk, Set(sig), None)
        val orderedWUs: IList[WorkUnit[Global]] = cg.topologicalSort(true).map { sig =>
          val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new IntentWu(apk, method, sm, handler, store, "intent")
        }
        analysis.build(orderedWUs)
        val candidate = store.getPropertyOrElse[MSet[(Context, PTASlot)]]("intent", msetEmpty)
        var intent: Option[Intent] = None
        candidate.foreach { case (ctx, s) =>
          val intentInss = store.resolved.pointsToSet(ctx, s)
          intent = IntentHelper.getIntentContents(store.resolved, intentInss, ctx).headOption
        }
        assert(intent.isDefined && intent.get.toString == intentStr)
        if(!DEBUG) {
          ConverterUtil.cleanDir(outputUri)
        }
      }
    }
  }
}