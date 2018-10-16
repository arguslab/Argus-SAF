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

import org.antlr.v4.runtime.tree.ParseTree
import org.apache.commons.lang3.StringEscapeUtils
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util.Antlr4
import org.argus.jawa.flow.summary.grammar.SafsuParser._
import org.argus.jawa.flow.summary.susaf.rule._
import org.argus.jawa.flow.summary.grammar._

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
  with Antlr4.Visitor[SuRuleNode] {

  override def visitSummaryFile(ctx: SummaryFileContext): SuRuleNode = {
    var defaultTypes: Map[JawaType, Map[String, JawaType]] = Map()
    ctx.defaultType().asScala.foreach { dt =>
      val baseType = getChild[SuJavaType](dt.javaType(0)).typ
      val fieldName = dt.ID.getText
      val fieldType = getChild[SuJavaType](dt.javaType(1)).typ
      defaultTypes += baseType -> (defaultTypes.getOrElse(baseType, Map()) + (fieldName -> fieldType))
    }
    HeapSummaryFile(
      defaultTypes,
      ctx.summary.asScala.map { s =>
        val summary = getChild[HeapSummary](s)
        (summary.sig, summary)
      }.toMap
    )
  }

  override def visitSummary(ctx: SummaryContext): SuRuleNode =
    HeapSummary(new Signature(getUID(ctx.signature.UID.getText)), getChildren(ctx.suRule.asScala))

  override def visitClearRule(ctx: ClearRuleContext): SuRuleNode =
    ClearRule({
      if(ctx.suThis != null) getChild[SuThis](ctx.suThis)
      else if(ctx.arg != null) getChild[SuArg](ctx.arg)
      else getChild[SuGlobal](ctx.global)
    })

  override def visitBinaryRule(ctx: BinaryRuleContext): SuRuleNode =
    BinaryRule(getChild[RuleLhs](ctx.lhs), ctx.ops.getText match {
      case "+=" => Ops.`+=`
      case "-=" => Ops.`-=`
      case _ => Ops.`=`
    }, getChild[RuleRhs](ctx.rhs))

  override def visitSuThis(ctx: SuThisContext): SuRuleNode =
    SuThis(getOptChild[SuHeap](ctx.heap))

  override def visitArg(ctx: ArgContext): SuRuleNode =
    SuArg(ctx.Digits.getText.toInt, getOptChild[SuHeap](ctx.heap))

  override def visitGlobal(ctx: GlobalContext): SuRuleNode =
    SuGlobal(getUID(ctx.UID.getText), getOptChild[SuHeap](ctx.heap))

  override def visitClassOf(ctx: ClassOfContext): SuRuleNode =
    SuClassOf(getChild[RuleRhs](ctx.rhs), getChild[SuLocation](ctx.location))

  override def visitHeap(ctx: HeapContext): SuRuleNode =
    SuHeap(getChildren(ctx.heapAccess.asScala))

  override def visitFieldAccess(ctx: FieldAccessContext): SuRuleNode =
    SuFieldAccess(ctx.ID.getText)

  override def visitArrayAccess(ctx: ArrayAccessContext): SuRuleNode =
    SuArrayAccess()

  override def visitRet(ctx: RetContext): SuRuleNode =
    SuRet(getOptChild[SuHeap](ctx.heap))

  override def visitInstance(ctx: InstanceContext): SuRuleNode =
    SuInstance(getChild[SuType](ctx.`type`), getChild[SuLocation](ctx.location))

  override def visitJavaType(ctx: JavaTypeContext): SuRuleNode =
    SuJavaType({
      val outerTyp: String = ctx.ID.asScala.map(id => id.getText).mkString(".")
      val innerTyp: String = "$" + ctx.innerType().asScala.map(it => it.ID.getText).mkString("$")
      val typ: String = outerTyp + {if(innerTyp != "$") innerTyp else ""}
      val unknown = getOptChild(ctx.unknown).isDefined
      val indices = ctx.arrayAccess.size
      val jtyp = new JawaType(typ, indices)
      if(unknown) jtyp.toUnknown
      else jtyp
    })

  override def visitStringLit(ctx: StringLitContext): SuRuleNode =
    SuString({
      if(ctx.STRING != null) {
        val raw = ctx.STRING.getText
        val text = raw.substring(1, raw.length - 1)
        StringEscapeUtils.unescapeJava(text)
      }
      else {
        val raw = ctx.MSTRING.getText
        val text = raw.substring(3, raw.length - 3)
        StringEscapeUtils.unescapeJava(text)
      }
    })

  override def visitVirtualLocation(ctx: VirtualLocationContext): SuRuleNode =
    SuVirtualLocation()

  override def visitConcreteLocation(ctx: ConcreteLocationContext): SuRuleNode =
    SuConcreteLocation(ctx.ID.getText)

  private def getUID(text: String): String = text.substring(1, text.length - 1)
}