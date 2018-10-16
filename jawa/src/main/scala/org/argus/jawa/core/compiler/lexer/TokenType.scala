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

case class TokenType(name: String) {

//  def isNewline = this == Tokens.NEWLINE || this == Tokens.NEWLINES

  def isKeyword: Boolean = Tokens.KEYWORDS contains this

  def isComment: Boolean = Tokens.COMMENTS contains this

  def isId: Boolean = Tokens.IDS contains this

  def isLiteral: Boolean = Tokens.LITERALS contains this

  override lazy val toString: String = name

}
