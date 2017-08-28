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
import org.argus.jawa.alir.pta.PTAScopeManager
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.summary.wu.{HeapSummaryWu, WorkUnit}
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.susaf.rule.HeapSummary
import org.argus.jawa.summary.util.TopologicalSortUtil
import org.argus.jawa.summary.{BottomUpSummaryGenerator, JawaSummaryProvider, SummaryManager}
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
  * Created by fgwei on 6/30/17.
  */
class HeapSummaryGeneratorTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V" produce (
    """`Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V`:
      |  ~arg:0
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V" produce (
    """`Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V`:
      |  ~arg:0.myset
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V" produce (
    """`Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V`:
      |  ~arg:0.myarray[].myset
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearGlobal:()V" produce (
    """`Lcom/hugo/test/SingleFunction;.clearGlobal:()V`:
      |  ~`com.hugo.test.SingleFunction.myglobal`.myset
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearHeaps:()V" produce (
    """`Lcom/hugo/test/SingleFunction;.clearHeaps:()V`:
      |  ~`com.hugo.test.SingleFunction.myglobal`.myarray[].myself.myself.myself.myset
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;" produce (
    """`Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;`:
      |  arg:0.items += "Hello World!"@L1
      |  ret = arg:0.items
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;" produce (
    """`Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;`:
      |  arg:0.entries.key += "key"@L1
      |  arg:0.entries(arg:0.entries.key) = "value"@L2
      |  ret = arg:0.entries.key
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;" produce (
    """`Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;`:
      |  this.str += "Hello World!"@L1
      |  ret = this.str
      |;
    """.stripMargin,
  )

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;" produce (
    """`Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;`:
      |  this.myarray[] += "Hello World!"@L1
      |  this.str += "v1!"@L5
      |  arg:0.myset += java.util.HashSet@L7
      |  arg:0.myset.items += this.myarray[]
      |  this.myself = arg:0
      |  ret = this.str
      |;
    """.stripMargin,
  )

  class TestFile(file: String) {
    var entrypoint: Signature = _

    val handler = new ModelCallHandler(PTAScopeManager)

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(rule: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        implicit val heap: SimHeap = new SimHeap
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath), NoLibraryAPISummary.isLibraryClass)
        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        val cg = SignatureBasedCallGraph(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator(sm, handler,
          HeapSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed ETA: :eta"))
        val orderedWUs: IList[WorkUnit] = TopologicalSortUtil.sort(cg.getCallMap).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new HeapSummaryWu(method, sm, handler)
        }.reverse
        analysis.build(orderedWUs)
        val sm2: SummaryManager = new SummaryManager(global)
        sm2.register("test", rule, fileAndSubsigMatch = false)

        assert(sm.getSummary[HeapSummary](entrypoint).get.rules == sm2.getSummary[HeapSummary](entrypoint).get.rules)
      }
    }
  }
}
