/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.susaf.rule

import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.flow.summary.{Summary, SummaryRule}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
sealed trait SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class HeapSummaryFile(defaultTypes: Map[JawaType, Map[String, JawaType]], summaries: Map[Signature, HeapSummary]) extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class HeapSummary(sig: Signature, rules: Seq[HeapSummaryRule]) extends Summary[HeapSummaryRule] with SuRuleNode {
  override def toString: String = {
    s"""`${sig.signature}`:
      |  ${rules.mkString("\n  ")}
      |;
    """.stripMargin.trim.intern()
  }
}

trait HeapSummaryRule extends SummaryRule

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class ClearRule(v: HeapBase) extends HeapSummaryRule with SuRuleNode {
  override def toString: String = s"~$v".intern()
}

object Ops extends Enumeration {
  val `+=`, `-=`, `=` = Value
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class BinaryRule(lhs: RuleLhs, ops: Ops.Value, rhs: RuleRhs) extends HeapSummaryRule with SuRuleNode {
  override def toString: String = s"$lhs ${ops match {case Ops.`+=` => "+=" case Ops.`-=` => "-=" case Ops.`=` => "="}} $rhs"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait RuleLhs extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait RuleRhs extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait HeapBase extends RuleLhs with RuleRhs {
  def heapOpt: Option[SuHeap]
  def make(heapAccesses: Seq[HeapAccess]): HeapBase
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuThis(heapOpt: Option[SuHeap]) extends HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): SuThis = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuThis(Some(SuHeap(heap)))
  }

  override def toString: String = s"this${heapOpt match {case Some(heap) => heap case None => ""}}"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuArg(num: Int, heapOpt: Option[SuHeap]) extends HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): SuArg = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuArg(num, Some(SuHeap(heap)))
  }

  override def toString: String = s"arg:$num${heapOpt match {case Some(heap) => heap case None => ""}}"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuGlobal(fqn: String, heapOpt: Option[SuHeap]) extends HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): SuGlobal = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuGlobal(fqn, Some(SuHeap(heap)))
  }

  override def toString: String = s"`$fqn`${heapOpt match {case Some(heap) => heap case None => ""}}"
}

case class SuClassOf(rhs: RuleRhs, loc: SuLocation) extends RuleRhs {
  override def toString: String = s"classOf $rhs$loc"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuHeap(indices: Seq[HeapAccess]) extends SuRuleNode {
  override def toString: String = indices.mkString("")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait HeapAccess extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuFieldAccess(fieldName: String) extends HeapAccess {
  override def toString: String = s".$fieldName"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuArrayAccess() extends HeapAccess {
  override def toString: String = "[]"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuRet(heapOpt: Option[SuHeap]) extends HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): HeapBase = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuRet(Some(SuHeap(heap)))
  }

  override def toString: String = s"ret${heapOpt match {case Some(heap) => heap case None => ""}}"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuInstance(typ: SuType, loc: SuLocation) extends RuleRhs {
  override def toString: String = s"$typ$loc"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait SuType extends SuRuleNode {
  def typ: JawaType
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuJavaType(typ: JawaType) extends SuType {
  override def toString: String = typ.jawaName
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuString(str: String) extends SuType {
  def typ: JawaType = new JawaType("java.lang.String")

  override def toString: String = "\"" + str + "\""
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait SuLocation extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuVirtualLocation() extends SuLocation {
  override def toString: String = "@~"
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuConcreteLocation(loc: String) extends SuLocation {
  override def toString: String = s"@$loc"
}