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

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.alir.pta.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.core.{JawaType, Signature}
import org.argus.jawa.core.util._
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 6/8/17.
  */
class SummaryManagerTest extends FlatSpec with Matchers {
  "SummaryManager" should "handle += correctly" in {
    val code =
      """
        |`Lmy/Class;.foo:()Ljava/lang/String;`:
        |  ret += java.lang.String@L1
        |  ret += "String"@L1
        |;
      """.stripMargin
    implicit val factory = new SimHeap
    val sm = new SummaryManager
    sm.register(code)

    val calleeSig = new Signature("Lmy/Class;.foo:()Ljava/lang/String;")
    val retName = "temp"
    val context = new Context("Test")
    val expectedContext = context.copy.setContext(calleeSig, "L1")
    val expectedFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(retName, isBase = false, isArg = false), PTAPointStringInstance(expectedContext)),
        new RFAFact(VarSlot(retName, isBase = false, isArg = false), PTAConcreteStringInstance("String", expectedContext))
      )

    val currentFacts: ISet[RFAFact] = sm.process(calleeSig, Some(retName), None, ilistEmpty, isetEmpty, context)
    assert(currentFacts.size == expectedFacts.size && currentFacts.diff(expectedFacts).isEmpty)
  }

  "SummaryManager" should "handle = correctly" in {
    val code =
      """
        |`Lmy/Class;.foo:()V`:
        |  this.f1 = my.Class2@L1
        |  this.f1.f2 = my.Class3@L2
        |;
      """.stripMargin
    implicit val factory = new SimHeap
    val sm = new SummaryManager
    sm.register(code)

    val callerSig = new Signature("Lmy/Class;.main:()V")
    val calleeSig = new Signature("Lmy/Class;.foo:()V")
    val recvName = "v1"
    val context = new Context("Test")
    val recvContext = context.copy.setContext(callerSig, "L0")
    val expectedContext1 = context.copy.setContext(calleeSig, "L1")
    val expectedContext2 = context.copy.setContext(calleeSig, "L2")
    val recvIns = PTAInstance(new JawaType("my.Class"), recvContext)
    val expectedFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext1)),
        new RFAFact(FieldSlot(PTAInstance(new JawaType("my.Class2"), expectedContext1), "f2"), PTAInstance(new JawaType("my.Class3"), expectedContext2))
      )

    val initialFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), context.copy.setContext(callerSig, "L100"))),
        new RFAFact(FieldSlot(PTAInstance(new JawaType("my.Class2"), context.copy.setContext(callerSig, "L100")), "f2"), PTAInstance(new JawaType("my.Class3"), context.copy.setContext(callerSig, "L101")))
      )
    val currentFacts: ISet[RFAFact] = sm.process(calleeSig, None, Some(recvName), ilistEmpty, initialFacts, context)
    assert(currentFacts.size == expectedFacts.size && currentFacts.diff(expectedFacts).isEmpty)
  }

  "SummaryManager" should "handle -= correctly" in {
    val code =
      """
        |`Lmy/Class;.foo:()V`:
        |  this.f1 -= this.f2
        |;
      """.stripMargin
    implicit val factory = new SimHeap
    val sm = new SummaryManager
    sm.register(code)

    val callerSig = new Signature("Lmy/Class;.main:()V")
    val calleeSig = new Signature("Lmy/Class;.foo:()V")
    val recvName = "v1"
    val context = new Context("Test")
    val recvContext = context.copy.setContext(callerSig, "L0")
    val expectedContext1 = context.copy.setContext(calleeSig, "L1")
    val expectedContext2 = context.copy.setContext(calleeSig, "L2")
    val recvIns = PTAInstance(new JawaType("my.Class"), recvContext)
    val expectedFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext1)),
        new RFAFact(FieldSlot(recvIns, "f2"), PTAInstance(new JawaType("my.Class2"), expectedContext2))
      )

    val initialFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext1)),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext2)),
        new RFAFact(FieldSlot(recvIns, "f2"), PTAInstance(new JawaType("my.Class2"), expectedContext2))
      )
    val currentFacts: ISet[RFAFact] = sm.process(calleeSig, None, Some(recvName), ilistEmpty, initialFacts, context)
    assert(currentFacts.size == expectedFacts.size && currentFacts.diff(expectedFacts).isEmpty)
  }

  "SummaryManager" should "handle clear rule correctly" in {
    val code =
      """
        |`Lmy/Class;.foo:()V`:
        |  this.f1 -= this.f2
        |  ~this.f2
        |;
      """.stripMargin
    implicit val factory = new SimHeap
    val sm = new SummaryManager
    sm.register(code)

    val callerSig = new Signature("Lmy/Class;.main:()V")
    val calleeSig = new Signature("Lmy/Class;.foo:()V")
    val recvName = "v1"
    val context = new Context("Test")
    val recvContext = context.copy.setContext(callerSig, "L0")
    val expectedContext1 = context.copy.setContext(calleeSig, "L1")
    val expectedContext2 = context.copy.setContext(calleeSig, "L2")
    val recvIns = PTAInstance(new JawaType("my.Class"), recvContext)
    val expectedFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext1))
      )

    val initialFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext1)),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class2"), expectedContext2)),
        new RFAFact(FieldSlot(recvIns, "f2"), PTAInstance(new JawaType("my.Class2"), expectedContext2)),
        new RFAFact(FieldSlot(PTAInstance(new JawaType("my.Class2"), expectedContext2), "ff1"), PTAInstance(new JawaType("my.Class3"), context.copy.setContext(callerSig, "L100")))
      )
    val currentFacts: ISet[RFAFact] = sm.process(calleeSig, None, Some(recvName), ilistEmpty, initialFacts, context)
    assert(currentFacts.size == expectedFacts.size && currentFacts.diff(expectedFacts).isEmpty)
  }

  "SummaryManager" should "handle args correctly" in {
    val code =
      """
        |`Lmy/Class;.foo:(Lmy/Class2;Ljava/lang/String;)V`:
        |  this.f1 += arg:0.f1
        |  arg:0.f2 = "String"@L10
        |  this.f2 = arg:1
        |;
      """.stripMargin
    implicit val factory = new SimHeap
    val sm = new SummaryManager
    sm.register(code)

    val callerSig = new Signature("Lmy/Class;.main:()V")
    val calleeSig = new Signature("Lmy/Class;.foo:(Lmy/Class2;Ljava/lang/String;)V")
    val recvName = "v1"
    val argNames = List("v2", "v3")
    val context = new Context("Test")
    val recvContext = context.copy.setContext(callerSig, "L0")
    val expectedContext1 = context.copy.setContext(calleeSig, "L1")
    val expectedContext2 = context.copy.setContext(calleeSig, "L2")
    val expectedContext3 = context.copy.setContext(calleeSig, "L3")
    val expectedContext10 = context.copy.setContext(calleeSig, "L10")
    val recvIns = PTAInstance(new JawaType("my.Class"), recvContext)
    val arg0Ins = PTAInstance(new JawaType("my.Class2"), expectedContext1)
    val arg1Ins = PTAConcreteStringInstance("taint", expectedContext3)
    val expectedFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(FieldSlot(recvIns, "f1"), PTAInstance(new JawaType("my.Class3"), expectedContext2)),
        new RFAFact(FieldSlot(recvIns, "f2"), arg1Ins),
        new RFAFact(VarSlot(argNames.head, isBase = false, isArg = false), arg0Ins),
        new RFAFact(FieldSlot(arg0Ins, "f1"), PTAInstance(new JawaType("my.Class3"), expectedContext2)),
        new RFAFact(FieldSlot(arg0Ins, "f2"), PTAConcreteStringInstance("String", expectedContext10)),
        new RFAFact(VarSlot(argNames(1), isBase = false, isArg = false), arg1Ins)
      )

    val initialFacts: ISet[RFAFact] =
      Set(
        new RFAFact(VarSlot(recvName, isBase = false, isArg = false), recvIns),
        new RFAFact(VarSlot(argNames.head, isBase = false, isArg = false), arg0Ins),
        new RFAFact(FieldSlot(arg0Ins, "f1"), PTAInstance(new JawaType("my.Class3"), expectedContext2)),
        new RFAFact(VarSlot(argNames(1), isBase = false, isArg = false), arg1Ins)
      )
    val currentFacts: ISet[RFAFact] = sm.process(calleeSig, None, Some(recvName), argNames, initialFacts, context)
    assert(currentFacts.size == expectedFacts.size && currentFacts.diff(expectedFacts).isEmpty)
  }
}
