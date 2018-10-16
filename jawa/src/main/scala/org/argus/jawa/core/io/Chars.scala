/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.io

import java.lang.{Character => JCharacter}

import scala.annotation.switch
import scala.language.postfixOps

/** Contains constants and classifier methods for characters */
trait Chars {
  final val LF = '\u000A'
  final val FF = '\u000C'
  final val CR = '\u000D'
  final val SU = '\u001A'

  /** Convert a character digit to an Int according to given base,
   *  -1 if no success
   */
  def digit2int(ch: Char, base: Int): Int = {
    val num =
      if (ch <= '9') ch - '0'
      else if ('a' <= ch && ch <= 'z') ch - 'a' + 10
      else if ('A' <= ch && ch <= 'Z') ch - 'A' + 10
      else -1
    if (0 <= num && num < base) num else -1
  }
  /** Buffer for creating '\ u XXXX' strings. */
  private[this] val char2uescapeArray = Array[Char]('\\', 'u', 0, 0, 0, 0)

  /** Convert a character to a backslash-u escape */
  def char2uescape(c: Char): String = {
    @inline def hexChar(ch: Int): Char =
      ( if (ch < 10) '0' else 'A' - 10 ) + ch toChar

    char2uescapeArray(2) = hexChar(c >> 12     )
    char2uescapeArray(3) = hexChar((c >> 8) % 16)
    char2uescapeArray(4) = hexChar((c >> 4) % 16)
    char2uescapeArray(5) = hexChar(c % 16)

    new String(char2uescapeArray)
  }

  /** Is character a line break? */
  def isLineBreakChar(c: Char): Boolean = (c: @switch) match {
    case LF|FF|CR|SU  => true
    case _            => false
  }

  /** Is character a whitespace character (but not a new line)? */
  def isWhitespace(c: Char): Boolean =
    c == ' ' || c == '\t' || c == CR

  /** Can character form part of a doc comment variable $xxx? */
  def isVarPart(c: Char): Boolean =
    '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'

  def isIdentifierStart(c: Char): Boolean =
    (c == '`') || Character.isJavaIdentifierPart(c)

  def isIdentifierPart(c: Char, isGraveAccent: Boolean): Boolean = {
    (c != '`' || c != ' ') &&
    {if(isGraveAccent) {c == '.' || c == '/' || c == ';' || c == ':' || c == '_' || c == '(' || c == ')' || c == '<' || c == '>' || Character.isJavaIdentifierPart(c)} 
    else {c != '.' && Character.isJavaIdentifierPart(c)}}
  }

  def isSpecial(c: Char): Boolean = {
    val chtp = Character.getType(c)
    chtp == Character.MATH_SYMBOL.toInt || chtp == Character.OTHER_SYMBOL.toInt
  }

  private final val otherLetters = Set[Char]('\u0024', '\u005F')  // '$' and '_'
  private final val letterGroups = {
    import JCharacter._
    Set[Byte](LOWERCASE_LETTER, UPPERCASE_LETTER, OTHER_LETTER, TITLECASE_LETTER, LETTER_NUMBER)
  }
  def isJawaLetter(ch: Char): Boolean = letterGroups(JCharacter.getType(ch).toByte) || otherLetters(ch)

  def isOperatorPart(c: Char): Boolean = (c: @switch) match {
    case '+' | '-' | '/' | '\\' | '*' | '%' | '&' | '|' | '?' | '>' | '<' | '=' | '~' | ':' => true
    case a => isSpecial(a)
  }
}

object Chars extends Chars { }
