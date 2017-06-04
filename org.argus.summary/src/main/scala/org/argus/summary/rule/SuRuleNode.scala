/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.summary.rule

/**
  * Created by fgwei on 6/3/17.
  */
sealed trait SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
case class SummaryFile(summaries: Map[String, Summary]) extends SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
case class Summary(signature: String, rules: Seq[SuRule]) extends SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
case class SuRule(lhs: RuleLhs, rhs: RuleRhs) extends SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
trait RuleLhs extends SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
trait RuleRhs extends SuRuleNode

/**
  * Created by fgwei on 6/3/17.
  */
case class SuArg(num: Int) extends RuleLhs with RuleRhs

/**
  * Created by fgwei on 6/3/17.
  */
case class SuField(arg: SuArg, fields: Seq[String]) extends RuleLhs with RuleRhs

/**
  * Created by fgwei on 6/3/17.
  */
case class SuGlobal(fqn: String) extends RuleLhs with RuleRhs

/**
  * Created by fgwei on 6/3/17.
  */
case class SuRet() extends RuleLhs

/**
  * Created by fgwei on 6/3/17.
  */
case class SuType(typ: String, loc: Option[SuLocation]) extends RuleRhs

/**
  * Created by fgwei on 6/3/17.
  */
case class SuLocation(loc: String) extends SuRuleNode