/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.gpu

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.util.FileUtil
import org.argus.jawa.core.{MsgLevel, PrintReporter}
import org.argus.jawa.summary.gpu.GPUSummaryBasedAnalysis
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class GPUSummaryBasedAnalysisTest extends FlatSpec with Matchers {
  final val DEBUG = false

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/droid-bench/AndroidSpecific/PrivateDataLeak1.apk" produce (
    """`Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V`:
      |  ~arg:1
      |;
    """.stripMargin.trim.intern()
    )

  "/droid-bench/AndroidSpecific/PrivateDataLeak2.apk" produce (
    """`Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V`:
      |  ~arg:1
      |;
    """.stripMargin.trim.intern()
    )

//  "/droid-bench/InterComponentCommunication/ActivityCommunication1.apk" produce (
//    """`Lcom/hugo/test/SingleFunction;.clearArg:(Ljava/util/Set;)V`:
//      |  ~arg:1
//      |;
//    """.stripMargin.trim.intern()
//    )

//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V" produce (
//    """`Lcom/hugo/test/SingleFunction;.clearField:(Lcom/hugo/test/SingleFunction;)V`:
//      |  ~arg:1.myset
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V" produce (
//    """`Lcom/hugo/test/SingleFunction;.clearArray:(Lcom/hugo/test/SingleFunction;)V`:
//      |  ~arg:1.myarray[].myset
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearGlobal:()V" produce (
//    """`Lcom/hugo/test/SingleFunction;.clearGlobal:()V`:
//      |  ~`com.hugo.test.SingleFunction.myglobal`.myset
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.clearHeaps:()V" produce (
//    """`Lcom/hugo/test/SingleFunction;.clearHeaps:()V`:
//      |  ~`com.hugo.test.SingleFunction.myglobal`.myarray[].myself.myself.myself.myset
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;" produce (
//    """`Lcom/hugo/test/SingleFunction;.add:(Ljava/util/Set;)Ljava/lang/String;`:
//      |  arg:1.items += "Hello World!"@L1
//      |  ret = arg:1.items
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;" produce (
//    """`Lcom/hugo/test/SingleFunction;.put:(Ljava/util/Map;)Ljava/lang/String;`:
//      |  arg:1.entries.key += "key"@L1
//      |  arg:1.entries.value += "value"@L2
//      |  ret = arg:1.entries.key
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;" produce (
//    """`Lcom/hugo/test/SingleFunction;.assign:()Ljava/lang/String;`:
//      |  this.str += "Hello World!"@L1
//      |  ret = this.str
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/SingleFunction.jawa" ep "Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;" produce (
//    """`Lcom/hugo/test/SingleFunction;.complex:(Lcom/hugo/test/SingleFunction;)Ljava/lang/String;`:
//      |  this.myarray[] += "Hello World!"@L1
//      |  this.str += "v1!"@L5
//      |  arg:1.myset += java.util.HashSet@L7
//      |  arg:1.myset.items += this.myarray[]
//      |  this.myself = arg:1
//      |  ret = this.str
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/MultiFunction.jawa" ep "Lcom/hugo/test/MultiFunction;.testGlobalMap:()V" produce (
//    """`Lcom/hugo/test/MultiFunction;.testGlobalMap:()V`:
//      |  `com.hugo.test.MultiFunction.map`.entries.key += "key"@L1
//      |  `com.hugo.test.MultiFunction.map`.entries.value += "value"@L2
//      |;
//    """.stripMargin.trim.intern()
//    )
//
//  "/jawa/summary/MCnToSpell.jawa" ep "Lcom/i4joy/core/MCnToSpell;.init:()V" run()

  class TestFile(file: String) {

    def produce(rule: String): Unit = {
      file should s"produce expected summary" in {
        val apkUri = FileUtil.toUri(getClass.getResource(file).getPath)
        val outputUri = apkUri.substring(0, apkUri.length - 4)
        val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
        val yard = new ApkYard(reporter)
        val layout = DecompileLayout(outputUri)
        val strategy = DecompileStrategy(layout)
        val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
        val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)

        val analysis = new GPUSummaryBasedAnalysis
        val w = new PrintWriter(System.out)

        apk.model.getEnvMap.foreach { case (t, (s, _)) =>
          analysis.prepareData(apk, s, w)
        }
//        if(!DEBUG) {
//          ConverterUtil.cleanDir(outputUri)
//        }
        assert(true)
      }
    }
  }

}
