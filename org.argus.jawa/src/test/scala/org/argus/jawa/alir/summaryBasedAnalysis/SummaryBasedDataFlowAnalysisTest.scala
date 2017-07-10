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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.alir.pta.summaryBasedAnalysis.{JawaSummaryProvider, SummaryBasedDataFlowAnalysis, SummaryManager}
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
  * Created by fgwei on 6/30/17.
  */
class SummaryBasedDataFlowAnalysisTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.main:(Ljava/util/Set;)Ljava/lang/String;" with_input () produce ""

  class TestFile(file: String) {
    var entrypoint: Signature = _
    var input: ISet[RFAFact] = _

    val handler = new ModelCallHandler(new DefaultScopeManager)

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def with_input(input: RFAFact*): TestFile = {
      this.input = input.toSet
      this
    }

    def produce(string: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        implicit val heap = new SimHeap
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath), NoLibraryAPISummary.isLibraryClass)
        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        val cg = SignatureBasedCallGraph(global, Set(entrypoint), None)
        val analysis = new SummaryBasedDataFlowAnalysis(
          global, sm, handler, true,
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed ETA: :eta"))
        analysis.build(cg)
//        assert(output == expected.toSet)
      }
    }
  }
}
