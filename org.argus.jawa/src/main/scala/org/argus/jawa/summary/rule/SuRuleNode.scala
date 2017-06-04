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

import org.argus.jawa.core.Signature

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
sealed trait SuRuleNode

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SummaryFile(summaries: Map[Signature, Summary]) extends SuRuleNode

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
case class ClearRule(v: RuleLhs with RuleRhs) extends SuRule

object Ops extends Enumeration {
  val `+=`, `-=`, `=` = Value
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class BinaryRule(lhs: RuleLhs, ops: Ops.Value, rhs: RuleRhs) extends SuRule

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
case class SuThis(heapOpt: Option[SuHeap]) extends RuleLhs with RuleRhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuArg(num: Int, heapOpt: Option[SuHeap]) extends RuleLhs with RuleRhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuGlobal(fqn: String, heapOpt: Option[SuHeap]) extends RuleLhs with RuleRhs

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
case class SuRet(heapOpt: Option[SuHeap]) extends RuleLhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuType(typ: String, loc: SuLocation) extends RuleRhs

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