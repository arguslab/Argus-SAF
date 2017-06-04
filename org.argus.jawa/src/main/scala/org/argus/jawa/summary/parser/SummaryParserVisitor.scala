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

import org.antlr.v4.runtime.tree.ParseTree
import org.argus.jawa.core.util.Antlr4
import org.argus.jawa.summary.rule.{RuleRhs, SuArg, SuField, SuGlobal, SuLocation, SuRet, SuType, _}
import org.argus.jawa.summary.grammar.SafsuBaseVisitor
import org.argus.jawa.summary.grammar.SafsuParser._

import scala.collection.JavaConverters._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object SummaryParserVisitor {
  def apply[T <: SuRuleNode](t: ParseTree): T =
    new SummaryParserVisitor().
      visit(t).asInstanceOf[T]
}

class SummaryParserVisitor()
  extends SafsuBaseVisitor[SuRuleNode]
  with Antlr4.Visitor {

  override def visitSummaryFile(ctx: SummaryFileContext): SuRuleNode =
    SummaryFile(ctx.summary.asScala.map{ s =>
      val summary = getChild[Summary](s)
      (summary.signature, summary)
    }.toMap)

  override def visitSummary(ctx: SummaryContext): SuRuleNode =
    Summary(getSignature(ctx.signature), getChildren(ctx.suRule.asScala))

  override def visitSuRule(ctx: SuRuleContext): SuRuleNode =
    SuRule(getChild[RuleLhs](ctx.lhs), getChild[RuleRhs](ctx.rhs))

  override def visitArg(ctx: ArgContext): SuRuleNode =
    SuArg(ctx.Digits.getText.toInt)

  override def visitField(ctx: FieldContext): SuRuleNode =
    SuField(getChild[SuArg](ctx.arg), ctx.ID.asScala.map(_.getText))

  override def visitGlobal(ctx: GlobalContext): SuRuleNode =
    SuGlobal(ctx.ID.asScala.map(_.getText).mkString("."))

  override def visitRet(ctx: RetContext): SuRuleNode =
    SuRet()

  override def visitType(ctx: TypeContext): SuRuleNode =
    SuType(ctx.ID.asScala.map(_.getText).mkString("."), getOptChild[SuLocation](ctx.location))

  override def visitLocation(ctx: LocationContext): SuRuleNode =
    SuLocation(ctx.ID.getText)

  private def getSignature(ctx: SignatureContext): String = {
    val r = ctx.getText
    if (r.startsWith("`")) r.substring(1, r.length - 1) else r
  }
}