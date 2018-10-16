/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.lexer

object NoHiddenTokens extends HiddenTokens(Nil)

case class HiddenTokens(tokens: List[HiddenToken]) extends Iterable[HiddenToken] {

  def removeInitialWhitespace() = HiddenTokens(tokens.dropWhile(_.isInstanceOf[Whitespace]))

  def iterator: Iterator[HiddenToken] = tokens.iterator

  val comments: List[Comment] = tokens collect { case comment: Comment => comment }

  val whitespaces: List[Whitespace] = tokens collect { case whitespace @ Whitespace(_) => whitespace }

  def firstTokenOption: Option[HiddenToken] = tokens.headOption

  def lastTokenOption: Option[HiddenToken] = tokens.lastOption

  def containsNewline: Boolean = text contains '\n'

  def containsComment: Boolean = comments.nonEmpty

  def containsUnicodeEscape: Boolean = {
    for (token <- tokens if token.token.containsUnicodeEscape)
      return true
    false
  }

  lazy val text: String = {
    val sb = new StringBuilder
    for (token <- tokens) sb.append(token.text)
    sb.toString
  }
  
  def rawTokens: List[Token] = tokens.map(_.token)

  def offset: Int = tokens.head.token.pos.point

  def lastCharacterOffset: Int = tokens.last.token.lastCharacterOffset

}
