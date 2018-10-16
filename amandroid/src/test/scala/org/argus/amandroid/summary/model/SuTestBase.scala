/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.model

import org.argus.jawa.core.Global
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.DefaultReporter
import org.argus.jawa.core.util.{IList, ISet, isetEmpty}
import org.argus.jawa.flow.summary.SummaryManager
import org.argus.jawa.flow.summary.susaf.HeapSummaryProcessor
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
  * Created by fgwei on 6/16/17.
  */
abstract class SuTestBase(fileName: String) extends FlatSpec with Matchers {
  val reporter = new DefaultReporter
  val global = new Global("Test", reporter)
  global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
  val sm: SummaryManager = new SummaryManager(global)
  sm.registerFile("summaries/" + fileName, fileName, fileAndSubsigMatch = true)

  val context: Context = new Context("SuTest")
  val currentContext: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L888")
  val defContext: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L800")
  val defContext2: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L801")
  val defContext3: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L802")
  val defContext4: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L803")
  val defContext5: Context = context.copy.setContext(new Signature("Lmy/Class;.main:()V"), "L804")

  implicit def string2TestSignature(s: String): TestSignature =
    new TestSignature(new Signature(s))

  class TestSignature(signature: Signature) {
    var input: ISet[RFAFact] = _

    def with_input(input: RFAFact*): TestSignature = {
      this.input = input.toSet
      this
    }

    def produce(expected: RFAFact*): Unit = {
      signature.signature should "produce as expected" in {
        val summaries = sm.getSummariesByFile(fileName)
        val retOpt: Option[String] = Some("temp")
        val recvOpt: Option[String] = Some("v0")
        val args: IList[String] = (1 to signature.getParameterNum).map(i => "v" + i).toList
        val output: ISet[RFAFact] =
          summaries.get(signature.getSubSignature) match {
            case Some(summary) =>
              HeapSummaryProcessor.process(global, summary, retOpt, recvOpt, args, input, currentContext)
            case None =>
              isetEmpty
          }
        assert(output == expected.toSet)
      }
    }
  }
}