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

abstract sealed class HiddenToken(val token: Token) {

  lazy val newlineful: Boolean = token.text contains '\n'

  def text: String = token.text

}

case class Whitespace(override val token: Token) extends HiddenToken(token)

sealed abstract class Comment(token: Token) extends HiddenToken(token)

object Comment {

  def unapply(comment: Comment) = Some(comment.token)

}

case class SingleLineComment(override val token: Token) extends Comment(token)

case class MultiLineComment(override val token: Token) extends Comment(token)

case class DocComment(override val token: Token) extends Comment(token)
