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

import org.argus.jawa.core.io.{Position, SourceFile}

/**
 * A token of Jawa source.
 *
 * @param tokenType Token type.
 * @param pos Position in the text.
 * @param rawText the text associated with the token.
 */
case class Token(tokenType: TokenType, pos: Position, rawText: String) {

  private[lexer] var associatedWhitespaceAndComments_ : HiddenTokens = _

  private[lexer] var containsUnicodeEscape = false

  def associatedWhitespaceAndComments: HiddenTokens = associatedWhitespaceAndComments_
  
  def line: Int = pos.line
  
  def column: Int = pos.column
  
  def offset: Int = pos.point
  
  def length: Int = rawText.length

  def lastCharacterOffset: Int = pos.point + length - 1
  
  def file: SourceFile = pos.source
  
  def range: Range = Range(pos.start, pos.end - pos.start + 1)
  
  def text: String = {
    tokenType match {
      case Tokens.STATIC_ID | Tokens.ID =>
        rawText.replace("`", "")
      case _ => rawText
    }
  }
  
  override def toString: String = {
    var txt = text
    if (txt != null) {
      txt = txt.replace("\n","\\n")
      txt = txt.replace("\r","\\r")
      txt = txt.replace("\t","\\t")
    }
    else {
      txt = "<no text>"
    }
    "["+txt+",<"+tokenType+">"+"@"+pos+"]"
  }

}
