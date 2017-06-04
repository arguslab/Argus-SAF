/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.parser

import org.argus.jawa.core.Signature
import org.argus.jawa.summary.rule.{SuType, _}
import org.scalatest.{FlatSpec, Matchers}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SummaryParserTest extends FlatSpec with Matchers {

  "SummaryParser" should "not throw a parse exception on complete program" in {
    parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
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
        |;
      """.stripMargin.stripMargin)
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
    require(sf.summaries.size == 2)
    require(sf.summaries.contains(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;")))
    require(sf.summaries.contains(new Signature("Lcom/my/Class;.do2:(LO1;LO2;)LO3;")))
    require(sf.summaries.flatMap(_._2.rules).size == 8)
  }

  "SummaryParser" should "get arg" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules.head.lhs.isInstanceOf[SuArg]
      && s.get.rules.head.lhs.asInstanceOf[SuArg].num == 1)
  }

  "SummaryParser" should "get field and ret" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  ret=arg:1.field
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined && s.get.rules.head.lhs.isInstanceOf[SuRet])
    require(s.isDefined
      && s.get.rules.head.rhs.isInstanceOf[SuArg]
      && s.get.rules.head.rhs.asInstanceOf[SuArg].heapOpt.isDefined
      && s.get.rules.head.rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.isInstanceOf[SuFieldAccess]
      && s.get.rules.head.rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "field")
  }

  "SummaryParser" should "get global and type" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  `my.Class.Glo` = my.Class@L100
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules.head.lhs.isInstanceOf[SuGlobal]
      && s.get.rules.head.lhs.asInstanceOf[SuGlobal].fqn == "my.Class.Glo")
    require(s.isDefined
      && s.get.rules.head.rhs.isInstanceOf[SuType]
      && s.get.rules.head.rhs.asInstanceOf[SuType].typ == "my.Class"
      && s.get.rules.head.rhs.asInstanceOf[SuType].loc.loc == "L100")
  }

  "SummaryParser" should "get nested field and array" in {
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
        |  arg:2[]=arg:1.field
        |  arg:1=`com.my.Class.Glo`.f.f2[]
        |  `com.my.Class.Glo`.f.f2[]=arg:1.field
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules(3).rhs.asInstanceOf[SuArg].heapOpt.get.indices(5).asInstanceOf[SuFieldAccess].fieldName == "f6")
  }

  def parse(code: String): SummaryFile = {
    SummaryParser(code)
  }
}
