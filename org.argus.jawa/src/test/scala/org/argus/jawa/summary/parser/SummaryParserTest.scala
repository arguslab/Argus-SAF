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
        |  ~arg:1.f1
        |  this.f1[]=arg:1
        |  ret.f1=Class@~
        |;
      """.stripMargin.stripMargin)
  }

  "SummaryParser" should "not throw a parse exception on map model" in {
    parse(
      """`Ljava/util/Map;.clear:()V`:
        |  ~this
        |;
        |
        |`Ljava/util/Map;.clone:()Ljava/lang/Object;`:
        |  ret = this
        |;
        |
        |`Ljava/util/Map;.entrySet:()Ljava/util/Set;`:
        |  ret = java.util.HashSet@~
        |  ret.items = this.entries
        |;
        |
        |`Ljava/util/Map;.get:(Ljava/lang/Object;)Ljava/lang/Object;`:
        |  ret = this.entries.right // need to be improved
        |;
        |
        |`Ljava/util/Map;.keySet:()Ljava/util/Set;`:
        |  ret = java.util.HashSet@~
        |  ret.items = this.entries.left
        |;
        |
        |`Ljava/util/Map;.put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`:
        |  ret = this.entries.right
        |  this.entries.left += arg:0
        |  this.entries.right += arg:1
        |;
        |
        |`Ljava/util/Map;.putAll:(Ljava/util/Map;)V`:
        |  this.entries += arg:0.entries
        |;
        |
        |`Ljava/util/Map;.remove:(Ljava/lang/Object;)Ljava/lang/Object;`:
        |  ret = this.entries.right
        |  this.entries.left -= arg:0
        |;
        |
        |`Ljava/util/Map;.values:()Ljava/util/Collection;`:
        |  ret = java.util.HashSet@~
        |  ret.items = this.entries.right
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
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.asInstanceOf[SuArg].num == 1)
  }

  "SummaryParser" should "get field and ret" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  ret.f1=arg:1.field
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.isInstanceOf[SuRet]
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.asInstanceOf[SuRet].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "f1")
    require(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.isInstanceOf[SuArg]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.isInstanceOf[SuFieldAccess]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "field")
  }

  "SummaryParser" should "get global and type" in {
    val sf = parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  `my.Class.Glo` = my.Class@L100
        |  arg:1 = my.Class@~
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.isInstanceOf[SuGlobal]
      && s.get.rules.head.asInstanceOf[BinaryRule].lhs.asInstanceOf[SuGlobal].fqn == "my.Class.Glo")
    require(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.isInstanceOf[SuType]
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuType].typ == "my.Class"
      && s.get.rules.head.asInstanceOf[BinaryRule].rhs.asInstanceOf[SuType].loc.asInstanceOf[SuConcreteLocation].loc == "L100")
    require(s.isDefined
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.isInstanceOf[SuType]
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuType].typ == "my.Class"
      && s.get.rules(1).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuType].loc.isInstanceOf[SuVirtualLocation])
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
        |  ~arg:1.f1
        |  this.f1[] = arg:1
        |;
      """.stripMargin)
    val s = sf.summaries.get(new Signature("Lcom/my/Class;.do:(LO1;LO2;)LO3;"))
    require(s.isDefined
      && s.get.rules(3).asInstanceOf[BinaryRule].rhs.asInstanceOf[SuArg].heapOpt.get.indices(5).asInstanceOf[SuFieldAccess].fieldName == "f6")
    require(s.isDefined
      && s.get.rules(14).asInstanceOf[ClearRule].v.asInstanceOf[SuArg].heapOpt.get.indices.head.asInstanceOf[SuFieldAccess].fieldName == "f1")
    require(s.isDefined
      && s.get.rules(15).asInstanceOf[BinaryRule].lhs.asInstanceOf[SuThis].heapOpt.get.indices(1).isInstanceOf[SuArrayAccess])
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
    require(s.isDefined
      && s.get.rules.head.asInstanceOf[BinaryRule].ops == Ops.`+=`
      && s.get.rules(1).asInstanceOf[BinaryRule].ops == Ops.`-=`)
  }

  def parse(code: String): SummaryFile = {
    SummaryParser(code)
  }
}
