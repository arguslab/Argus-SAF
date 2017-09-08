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

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.model.Intent
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTASlot
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core.util._
import org.argus.jawa.core._
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jawa.summary.wu.{PTStore, PTSummary, WorkUnit}
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class IntentWuTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/jawa/intent/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.singleFunc:()V" produce (
    """
      |Intent:
      |  Component Names:
      |    org.arguslab.icc_explicit1.FooActivity
      |  Explicit: true
      |  Precise: true
    """.stripMargin.trim
  )

  "/jawa/intent/MainActivity.jawa" ep "Lorg/arguslab/icc_explicit1/MainActivity;.caller:()V" produce (
    """
      |Intent:
      |  Component Names:
      |    org.arguslab.icc_explicit1.FooActivity
      |  Explicit: true
      |  Precise: true
    """.stripMargin.trim
    )

  class TestFile(file: String) {
    var entrypoint: Signature = _

    val handler: AndroidModelCallHandler.type = AndroidModelCallHandler

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(intentStr: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        implicit val heap: SimHeap = new SimHeap
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath), NoLibraryAPISummary.isLibraryClass)
        val sm: SummaryManager = new AndroidSummaryProvider(global).getSummaryManager
        val cg = SignatureBasedCallGraph(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator(sm, handler,
          PTSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed ETA: :eta"))
        val store: PTStore = new PTStore
        val orderedWUs: IList[WorkUnit] = cg.topologicalSort(true).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new IntentWu(method, sm, handler, store)
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
}