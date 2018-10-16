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

import Tokens._
import scala.collection.mutable.ListBuffer

class WhitespaceAndCommentsGrouper(lexer: JawaLexer) extends Iterator[Token] {

  private var nextToken = lexer.next()

  private var ended = false

  private var hiddenTokens: HiddenTokens = _

  def getHiddenTokens: HiddenTokens = hiddenTokens

  def hasNext: Boolean = !ended

  private[lexer] def text = lexer.text

  def next(): Token = {
    require(hasNext)
    hiddenTokens = readHiddenTokens()
    val resultToken = nextToken
    resultToken.associatedWhitespaceAndComments_ = hiddenTokens
    if (nextToken.tokenType == EOF)
      ended = true
    nextToken = lexer.next()
    resultToken
  }

  private def readHiddenTokens(): HiddenTokens = {
    val hiddenTokens = new ListBuffer[HiddenToken]
    while (isCommentOrWhitespace(nextToken)) {
      hiddenTokens += makeHiddenToken(nextToken)
      nextToken = lexer.next()
    }
    HiddenTokens(hiddenTokens.toList)
  }

  private def isCommentOrWhitespace(token: Token) = token.tokenType match {
    case WS | LINE_COMMENT | MULTILINE_COMMENT | DOC_COMMENT => true
    case _                                                   => false
  }

  private def makeHiddenToken(token: Token) = token.tokenType match {
    case LINE_COMMENT => SingleLineComment(token)
    case MULTILINE_COMMENT => MultiLineComment(token)
    case DOC_COMMENT => DocComment(token)
    case WS => Whitespace(token)
    case _ => throw new JawaLexerException(token.pos, "Unexpected HiddenToken: " + token)
  }

}
