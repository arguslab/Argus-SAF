/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.jawa.flow.pta.PTAScopeManager
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cg.CHA
import org.argus.jawa.flow.summary.susaf.rule.{HeapSummary, HeapSummaryRule}
import org.argus.jawa.flow.summary.wu.{HeapSummaryWu, WorkUnit}
import org.scalatest.tagobjects.Slow
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

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V" produce
    """`Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V`:
      |  ~arg:1
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V" produce
    """`Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V`:
      |  ~arg:1.myset
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V" produce
    """`Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V`:
      |  ~arg:1.myarray[].myset
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearGlobal:()V" produce
    """`Lcom/hugo/test/SingleFunction;.clearGlobal:()V`:
      |  ~`com.hugo.test.SingleFunction.myglobal`.myset
      |;
    """.stripMargin.trim.intern()

//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearHeaps:()V" produce
//    """`Lcom/hugo/test/SingleFunction;.clearHeaps:()V`:
//      |  ~`com.hugo.test.SingleFunction.myglobal`.myarray[].myself.myself.myself.myset
//      |;
//    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;" produce
    """`Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;`:
      |  arg:1.items += "Hello World!"@L1
      |  ret = arg:1.items
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;" produce
    """`Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;`:
      |  arg:1.entries.key += "key"@L1
      |  arg:1.entries.value += "value"@L2
      |  ret = arg:1.entries.key
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;" produce
    """`Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;`:
      |  this.str += "Hello World!"@L1
      |  ret = this.str
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;" produce
    """`Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;`:
      |  this.myarray[] += "Hello World!"@L1
      |  this.str += "v1!"@L5
      |  arg:1.myset += java.util.HashSet@L7
      |  arg:1.myset.items += this.myarray[]
      |  this.myself = arg:1
      |  ret = this.str
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/MultiFunction.jawa" ep "Lcom/hugo/test/MultiFunction;.testGlobalMap:()V" produce
    """`Lcom/hugo/test/MultiFunction;.testGlobalMap:()V`:
      |  `com.hugo.test.MultiFunction.map`.entries.key += "key"@L1
      |  `com.hugo.test.MultiFunction.map`.entries.value += "value"@L2
      |;
    """.stripMargin.trim.intern()

  "/jawa/summary/MCnToSpell.jawa" ep "Lcom/i4joy/core/MCnToSpell;.init:()V" run()

  class TestFile(file: String) {
    var entrypoint: Signature = _

    val handler = new ModelCallHandler(PTAScopeManager)

    def ep(sigStr: String): TestFile = {
      entrypoint = new Signature(sigStr)
      this
    }

    def run(): Unit = {
      file should s"finish for $entrypoint" taggedAs Slow in {
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath))
        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        val cg = CHA(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator[Global, HeapSummaryRule](global, sm, handler,
          HeapSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val orderedWUs: IList[WorkUnit[Global, HeapSummaryRule]] = cg.topologicalSort(true).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new HeapSummaryWu(global, method, sm, handler)
        }
        analysis.build(orderedWUs)
      }
    }

    def produce(rule: String): Unit = {
      file should s"produce expected summary for $entrypoint" in {
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val global = new Global("Test", reporter)
        global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
        global.load(FileUtil.toUri(getClass.getResource(file).getPath))
        val sm: SummaryManager = new JawaSummaryProvider(global).getSummaryManager
        val cg = CHA(global, Set(entrypoint), None)
        val analysis = new BottomUpSummaryGenerator[Global, HeapSummaryRule](global, sm, handler,
          HeapSummary(_, _),
          ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
        val orderedWUs: IList[WorkUnit[Global, HeapSummaryRule]] = cg.topologicalSort(true).map { sig =>
          val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
          new HeapSummaryWu(global, method, sm, handler)
        }
        analysis.build(orderedWUs)
        assertResult(rule)(sm.getSummary[HeapSummary](entrypoint).get.toString)
      }
    }
  }
}
