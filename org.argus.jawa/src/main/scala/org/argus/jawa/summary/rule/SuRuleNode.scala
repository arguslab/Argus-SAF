/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.rule

import org.argus.jawa.core.{JawaType, Signature}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
sealed trait SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SummaryFile(defaultTypes: Map[JawaType, Map[String, JawaType]], summaries: Map[Signature, Summary]) extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class Summary(signature: Signature, rules: Seq[SuRule]) extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait SuRule extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class ClearRule(v: HeapBase) extends SuRule

object Ops extends Enumeration {
  val `+=`, `-=`, `=` = Value
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class BinaryRule(lhs: RuleLhs, ops: Ops.Value, rhs: RuleRhs) extends SuRule

trait HeapBase extends RuleLhs {
  def heapOpt: Option[SuHeap]
  def make(heapAccesses: Seq[HeapAccess]): HeapBase
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
case class SuThis(heapOpt: Option[SuHeap]) extends RuleRhs with HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): HeapBase = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuThis(Some(SuHeap(heap)))
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuArg(num: Int, heapOpt: Option[SuHeap]) extends RuleRhs with HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): HeapBase = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuArg(num, Some(SuHeap(heap)))
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuGlobal(fqn: String, heapOpt: Option[SuHeap]) extends RuleRhs with HeapBase {
  def make(heapAccesses: Seq[HeapAccess]): HeapBase = {
    val heap: Seq[HeapAccess] = heapOpt match {
      case Some(h) => h.indices ++ heapAccesses
      case None => heapAccesses
    }
    SuGlobal(fqn, Some(SuHeap(heap)))
  }
}

case class SuClassOf(rhs: RuleRhs, loc: SuLocation) extends RuleRhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuHeap(indices: Seq[HeapAccess]) extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait HeapAccess extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuFieldAccess(fieldName: String) extends HeapAccess

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuArrayAccess() extends HeapAccess

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuMapAccess(rhsOpt: Option[RuleRhs]) extends HeapAccess

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
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuInstance(typ: SuType, loc: SuLocation) extends RuleRhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait SuType extends SuRuleNode {
  def typ: JawaType
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuJavaType(typ: JawaType) extends SuType

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuString(str: String) extends SuType {
  def typ: JawaType = new JawaType("java.lang.String")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
trait SuLocation extends SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuVirtualLocation() extends SuLocation

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuConcreteLocation(loc: String) extends SuLocation