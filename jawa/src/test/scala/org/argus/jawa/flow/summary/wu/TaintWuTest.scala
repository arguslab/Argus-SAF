/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
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
      |api_source: #L3.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L5.  call `sink`(TaintData_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L3.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L5.  call `sink`(TaintData_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.singleFunc2:()V" produce
    """
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller:()V" produce
    """Taint path:
      |api_source: #L12.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L17.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L12.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L15.  call `TaintTest.direct_sink`(`this`, TaintData_v0) @signature `LTaintTest;.direct_sink:(Ljava/lang/Object;)V` @kind virtual;
      |	-> Entry@LTaintTest;.direct_sink:(Ljava/lang/Object;)V param: 1
      |	-> #L17.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller2:()V" produce
    """Taint path:
      |api_source: #L19.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L19.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L23.  call `field_sink`(`this`) @signature `LTaintTest;.field_sink:()V` @kind virtual;
      |	-> Entry@LTaintTest;.field_sink:()V param: 0
      |	-> #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller3:()V" produce
    """Taint path:
      |api_source: #L34.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L34.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L36.  return TaintData_v0 @kind object;
      |	-> #L34.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L36.  return TaintData_v0 @kind object;
      |	-> #L28.  call TaintData_temp:= `direct_source`(`this`) @signature `LTaintTest;.direct_source:()LTaintData;` @kind static;
      |	-> #L32.  call `field_sink`(`this`) @signature `LTaintTest;.field_sink:()V` @kind virtual;
      |	-> Entry@LTaintTest;.field_sink:()V param: 0
      |	-> #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller4:()V" produce
    """Taint path:
      |api_source: #L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> Exit@LTaintTest;.field_source:()V param: 0
      |	-> #L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> Exit@LTaintTest;.field_source:()V param: 0
      |	-> #L41.  call `field_source`(`this`) @signature `LTaintTest;.field_source:()V` @kind virtual;
      |	-> #L42.  call `field_sink`(`this`) @signature `LTaintTest;.field_sink:()V` @kind virtual;
      |	-> Entry@LTaintTest;.field_sink:()V param: 0
      |	-> #L26.  call `sink`(Object_v0) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller5:()V" produce
    """Taint path:
      |api_source: #L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L45.  call `sink`(`this`) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> Exit@LTaintTest;.field_source:()V param: 0
      |	-> #L37.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> Exit@LTaintTest;.field_source:()V param: 0
      |	-> #L44.  call `field_source`(`this`) @signature `LTaintTest;.field_source:()V` @kind virtual;
      |	-> #L45.  call `sink`(`this`) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller6:()V" produce
    """Taint path:
      |api_source: #L47.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> api_sink: #L50.  call `sink`(`this`) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L47.  call TaintData_temp:= `source`() @signature `LTest;.source:()LTaintData;` @kind static;
      |	-> #L50.  call `sink`(`this`) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
    """.stripMargin.trim

  "/jawa/taint/TaintTest.jawa" ep "LTaintTest;.caller7:()V" produce
    """Taint path:
      |api_source: #L3.  call `source`(Data_v0) @signature `LTest;.source:(LData;)V` @kind static;
      |	-> api_sink: #L5.  call `sink`(String_v1) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
      |#L3.  call `source`(Data_v0) @signature `LTest;.source:(LData;)V` @kind static;
      |	-> #L5.  call `sink`(String_v1) @signature `LTest;.sink:(Ljava/lang/Object;)V` @kind static;
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
        println(path)
        assert(path == tp)
      }
    }
  }
}