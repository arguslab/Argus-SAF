/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util.{FileUtil, IList, TopologicalSortUtil}
import org.argus.jawa.flow.cg.CHA
import org.argus.jawa.flow.summary.susaf.rule.{HeapSummary, HeapSummaryRule}
import org.argus.jawa.flow.summary.wu.{HeapSummaryWu, WorkUnit}
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
  * Created by fgwei on 8/1/17.
  */
//noinspection ScalaUnnecessaryParentheses
class HeapSummaryGeneratorTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/jawa/icc_explicit1/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.leakImei:()V" produce (
    """`Lorg/arguslab/icc_explicit1/MainActivity;.leakImei:()V`:
      |;
    """.stripMargin
  )

  "/jawa/icc_explicit1/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.onCreate:(Landroid/os/Bundle;)V" produce (
    """`Lorg/arguslab/icc_explicit1/MainActivity;.onCreate:(Landroid/os/Bundle;)V`:
      |;
    """.stripMargin
  )

  "/jawa/icc_explicit1/FooActivity.jawa" ep "Lorg/arguslab/icc_explicit1/FooActivity;.onCreate:(Landroid/os/Bundle;)V" produce (
    """`Lorg/arguslab/icc_explicit1/FooActivity;.onCreate:(Landroid/os/Bundle;)V`:
      |
      |;
    """.stripMargin
  )

  class TestFile(file: String) {
    var entrypoint: Signature = _

    val handler: AndroidModelCallHandler = new AndroidModelCallHandler

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(rule: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath))
        val sm: SummaryManager = new AndroidSummaryProvider(global).getSummaryManager
        val cg = CHA(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator[Global, HeapSummaryRule](global, sm, handler,
          HeapSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val orderedWUs: IList[WorkUnit[Global, HeapSummaryRule]] = TopologicalSortUtil.sort(cg.getCallMap).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new HeapSummaryWu(global, method, sm, handler)
        }.reverse
        analysis.build(orderedWUs)
        val sm2: SummaryManager = new SummaryManager(global)
        sm2.register("test", rule, fileAndSubsigMatch = false)

        assert(sm.getSummary[HeapSummary](entrypoint).get.rules == sm2.getSummary[HeapSummary](entrypoint).get.rules)
      }
    }
  }
}
