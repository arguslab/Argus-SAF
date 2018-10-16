/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.susaf.parser

import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.flow.summary.susaf.rule._
import org.scalatest.{FlatSpec, Matchers}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryParserTest extends FlatSpec with Matchers {

  "SummaryParser" should "not throw a parse exception on complete program" in {
    parse(
      """android.content.Context:mBase:android.content.Context;
        |
        |`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |  arg:1.f1=arg:2.f2[]
        |  ret=arg:1.field.f3[]
        |  arg:1.f2=arg:2
        |  ret=arg:1.field
        |  arg:1[]=arg:2[][]
        |  ret=arg:1.field[][].length
        |  arg:1[][]=arg:2[]
        |  ret=arg:1.field.f3
        |  arg:1.f1=arg:2[]
        |  arg:2[]=arg:1.field
        |  arg:1=`com.my.Class.Glo`.f.f2[]
        |  `com.my.Class.Glo`.f.f2[]=arg:1.field
        |  ~arg:1.f1
        |  this.f1[]=arg:1
        |  ret.f1=Class$InnerClass?[][]@~
        |  ret.f2="String"@L1
        |  `com.my.Class.Glo`.f2=classOf this @~
        |;
      """.stripMargin)
  }

  "SummaryParser" should "throw a parse exception on bad program" in {
    an [SummaryParserException] should be thrownBy {
      parse(
        """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
          |  arg:1=
          |  ret=arg:1.field
          |;
        """.stripMargin)
    }
  }

  "SummaryParser" should "handle default type" in {
    val sf = parse(
      """android.content.Context:mBase:android.content.Context;
        |android.content.Context:mName:java.lang.String;
        |android.content.ContextWrapper:mIntent:android.content.Intent;
      """.stripMargin)
    assert(sf.defaultTypes.size == 2)
    assert(sf.defaultTypes.contains(new JawaType("android.content.Context")))
    assert(sf.defaultTypes(new JawaType("android.content.Context"))("mBase") == new JawaType("android.content.Context"))
    assert(sf.defaultTypes(new JawaType("android.content.Context"))("mName") == new JawaType("java.lang.String"))
  }

  "SummaryParser" should "have expected output" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |  `my.Class.Glo` = arg:1
        |  `my.Class.Glo2` = my.Class2@L100
        |;
        |`Lcom/my/Class;.do2:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |  `my.Class.Glo` = arg:1
        |  `my.Class.Glo2` = my.Class2@L100
        |;
      """.stripMargin)
    assert(sf.summaries.size == 2)
    assert(sf.summaries.contains(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;")))
    assert(sf.summaries.contains(new Signature("Lcom/my/Class;.do2:(LO1;LO2;)LO3;")))
    assert(sf.summaries.flatMap(_._2.rules).size == 8)
  }

  "SummaryParser" should "get arg" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.asInstanceOf[SuArg].num == 1)
  }

  "SummaryParser" should "get field and ret" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  ret=arg:1.field
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.isInstanceOf[SuRet])
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.isInstanceOf[SuArg]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.isInstanceOf[SuFieldAccess]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "field")
  }

  "SummaryParser" should "get global and type" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  `my.Class.Glo` = my.Class@L100
        |  arg:2 = my.Class@~
        |  arg:1 = my.Class$InnerClass@~
        |  arg:2.f1 = "str"@L1
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.isInstanceOf[SuGlobal]
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.asInstanceOf[SuGlobal].fqn == "my.Class.Glo")
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.isInstanceOf[SuInstance]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].typ.typ.jawaName == "my.Class"
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].loc.asInstanceOf[SuConcreteLocation].loc == "L100")
    assert(s.isDefined
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.isInstanceOf[SuInstance]
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].typ.typ.jawaName == "my.Class"
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].loc.isInstanceOf[SuVirtualLocation])
    assert(s.isDefined
      && s.get.rules(2).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].typ.typ.jawaName == "my.Class$InnerClass")
    assert(s.isDefined
      && s.get.rules(3).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].typ.asInstanceOf[SuString].str == "str")
  }

  "SummaryParser" should "get nested field and array and map" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |  arg:1.f1=arg:2.f2[]
        |  ret=arg:1.field.f3[].f4.f5.f6[].f7[][].f8
        |  arg:1.f2=arg:2
        |  ret=arg:1.field
        |  arg:1[]=arg:2[][]
        |  ret=arg:1.field[][].length
        |  arg:1[][]=arg:2[]
        |  ret=arg:1.field.f3
        |  arg:1.f1=arg:2[]
        |  arg:1=`com.my.Class.Glo`.f.f2[]
        |  ~arg:1.f1
        |  this.f1[] = arg:1
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules(3).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices(5).asInstanceOf[SuFieldAccess].fieldName == "f6")
    assert(s.isDefined
      && s.get.rules(12).asInstanceOf[ClearRule].v.asInstanceOf[SuArg].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "f1")
    assert(s.isDefined
      && s.get.rules(13).asInstanceOf[BinaryRule].lhs.asInstanceOf[SuThis].heapOpt.get.indices(1).isInstanceOf[SuArrayAccess])
  }

  "SummaryParser" should "get ops" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  `my.Class.Glo` += my.Class@L100
        |  arg:1 -= my.Class@~
        |  arg:1 = arg:2
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].ops == Ops.`+=`
      && s.get.rules(1).asInstanceOf[BinaryRule].ops == Ops.`-=`)
  }

  "SummaryParser" should "handle unknown" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1.f1 = my.Class?@~
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuInstance].typ.typ.baseType.unknown)
  }

  "SummaryParser" should "handle classOf" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1.f1 = classOf arg:0 @~
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    assert(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.isInstanceOf[SuClassOf])
  }

  def parse(code: String): HeapSummaryFile = {
    SummaryParser(code)
  }
}
