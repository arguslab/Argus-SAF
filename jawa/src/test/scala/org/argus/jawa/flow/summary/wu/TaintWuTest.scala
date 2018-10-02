/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.wu

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.jawa.flow.pta.PTAScopeManager
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.taintAnalysis.{SSPosition, SourceAndSinkManager}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cg.CHA
import org.argus.jawa.flow.summary.store.TaintStore
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, JawaSummaryProvider, SummaryManager}
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class TaintWuTest extends FlatSpec with Matchers {
  final val DEBUG = false

  class TestSSM extends SourceAndSinkManager[Global] {
    override def sasFilePath: String = ""
    addSource(new Signature("LTest;.source:()LTaintData;"), isetEmpty, Set("Test"))
    addSource(new Signature("LTest;.source:(LData;)V"), Set(new SSPosition("1.str")), Set("Test"))
    addSink(new Signature("LTest;.sink:(Ljava/lang/Object;)V"), Set(new SSPosition(1)), Set("Test"))
  }

  trait MyTest {
    def ep(sigStr: String): MyTest
    def produce(intentStr: String): Unit
  }

  implicit def file(file: String): MyTest = {
    new TestFile(file)
  }

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.singleFunc:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.singleFunc,L3)
      |	-> Call@(TaintTest.singleFunc,L5) param: 1
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.singleFunc2:()V" produce
    """
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.caller,L12)
      |	-> Call@(TaintTest.caller,L15) param: 1
      |	-> Call@(TaintTest.direct_sink,L17) param: 1
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller2:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.caller2,L19)
      |	-> Call@(TaintTest.caller2,L23) param: 0
      |	-> Call@(TaintTest.field_sink,L26) param: 1
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller3:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.direct_source,L34)
      |	-> Call@(TaintTest.caller3,L32) param: 0
      |	-> Call@(TaintTest.field_sink,L26) param: 1
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller4:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.field_source,L37)
      |	-> Call@(TaintTest.caller4,L42) param: 0
      |	-> Call@(TaintTest.field_sink,L26) param: 1
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller5:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.field_source,L37)
      |	-> Call@(TaintTest.caller5,L45) param: 1
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller6:()V" produce
    """Taint path:
      |api_source: LTest;.source:()LTaintData;
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.caller6,L47)
      |	-> Call@(TaintTest.caller6,L50) param: 1
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller7:()V" produce
    """Taint path:
      |api_source: LTest;.source:(LData;)V 1.str
      |	-> api_sink: LTest;.sink:(Ljava/lang/Object;)V 1
      |Call@(TaintTest.caller7,L3) param: 1.str
      |	-> Call@(TaintTest.caller7,L5) param: 1
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller8:()V" produce
    """
    """.stripMargin.trim

  class TestFile(file: String) extends MyTest {
    var entrypoint: Signature = _

    val handler: ModelCallHandler = new ModelCallHandler(PTAScopeManager)

    def ep(sigStr: String): MyTest = {
      entrypoint = new Signature(sigStr)
      this
    }

    def produce(tp: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath))

        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        sm.registerExternalFile(FileUtil.toUri(getClass.getResource("/jawa/taint/TaintAPI.safsu").getPath), "TaintAPI.safsu", fileAndSubsigMatch = false)
        val cg = CHA(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator[Global, TaintSummaryRule](global, sm, handler,
          TaintSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val store = new TaintStore
        val orderedWUs: IList[WorkUnit[Global, TaintSummaryRule]] = cg.topologicalSort(true).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new TaintWu(global, method, sm, handler, new TestSSM, store)
        }
        analysis.build(orderedWUs)
        val path = store.getTaintedPaths.mkString("\n").trim
        assert(path == tp)
      }
    }
  }
}