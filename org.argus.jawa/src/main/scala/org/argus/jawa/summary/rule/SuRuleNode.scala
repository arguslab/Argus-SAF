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
case class SuRule(lhs: RuleLhs, rhs: RuleRhs) extends SuRuleNode

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
case class SuArg(num: Int, heapOpt: Option[SuHeap]) extends RuleLhs with RuleRhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuGlobal(fqn: String, heapOpt: Option[SuHeap]) extends RuleLhs with RuleRhs

case class SuHeap(indices: Seq[HeapAccess]) extends SuRuleNode

trait HeapAccess extends SuRuleNode

case class SuFieldAccess(fieldName: String) extends HeapAccess
case class SuArrayAccess() extends HeapAccess

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuRet() extends RuleLhs

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class SuType(typ: String, loc: SuLocation) extends RuleRhs

case class SuLocation(loc: String) extends SuRuleNode