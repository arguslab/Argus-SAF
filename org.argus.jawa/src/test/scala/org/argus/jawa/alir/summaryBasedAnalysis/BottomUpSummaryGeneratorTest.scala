/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.rule._
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
  * Created by fgwei on 6/30/17.
  */
class BottomUpSummaryGeneratorTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V" produce (
    ClearRule(SuArg(0, None)),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V" produce (
    ClearRule(SuArg(0, Some(SuHeap(List(SuFieldAccess("myset")))))),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V" produce (
    ClearRule(SuArg(0, Some(SuHeap(List(SuFieldAccess("myarray"), SuArrayAccess(), SuFieldAccess("myset")))))),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearGlobal:()V" produce (
    ClearRule(SuGlobal("com.hugo.test.SingleFunction.myglobal", Some(SuHeap(List(SuFieldAccess("myset")))))),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearHeaps:()V" produce (
    ClearRule(SuGlobal("com.hugo.test.SingleFunction.myglobal",
      Some(
        SuHeap(List(
          SuFieldAccess("myarray"),
          SuArrayAccess(),
          SuFieldAccess("myself"),
          SuFieldAccess("myself"),
          SuFieldAccess("myself"),
          SuFieldAccess("myset")))))),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;" produce (
    BinaryRule(
      SuArg(0, Some(SuHeap(List(SuFieldAccess("items"))))),
      Ops.`+=`,
      SuInstance(SuString("Hello World!"), SuConcreteLocation("L1"))
    ),
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;" produce (
    BinaryRule(
      SuArg(0, Some(SuHeap(List(SuFieldAccess("entries"), SuFieldAccess("key"))))),
      Ops.`+=`,
      SuInstance(SuString("key"), SuConcreteLocation("L1"))
    ),
    BinaryRule(
      SuArg(0, Some(SuHeap(List(SuFieldAccess("entries"), SuMapAccess(Some(SuArg(0, Some(SuHeap(List(SuFieldAccess("entries"), SuFieldAccess("key"))))))))))),
      Ops.`=`,
      SuInstance(SuString("value"), SuConcreteLocation("L2"))
    ),
  )

  class TestFile(file: String) {
    var entrypoint: Signature = _

    val handler = new ModelCallHandler(new DefaultScopeManager)

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(expected: SuRule*): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        implicit val heap = new SimHeap
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath), NoLibraryAPISummary.isLibraryClass)
        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        val cg = SignatureBasedCallGraph(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator(
          global, sm, handler, true,
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed ETA: :eta"))
        analysis.build(cg)
        assert(sm.getSummary(entrypoint).get.rules.toList == expected.toList)
      }
    }
  }
}
