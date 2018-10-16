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

import org.argus.jawa.core.compiler.lexer.Tokens._
import org.argus.jawa.core.io.DefaultReporter
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

/**
 * Test full tokeniser.
 */
class WhitespaceAndCommentsGrouperTest extends FlatSpec with Matchers {

  implicit def string2TestString(s: String): TestString =
    new TestString(s)

  """
     #L1.   switch  v7
                 | 1 => goto Lx
                 | else => goto Ly;""" shouldProduceTokens (
    LOCATION_ID, SWITCH, ID,
    OP, INTEGER_LITERAL, ARROW, GOTO, ID,
    OP, ELSE, ARROW, GOTO, ID, SEMI)

  class TestString(s: String) {

    def shouldProduceTokens(toks: TokenType*)() {
      check(s, toks.toList)
    }

    private def check(s: String, expectedTokens: List[TokenType]) {
      it should ("tokenise >>>" + s + "<<< as >>>" + expectedTokens + "<<<") in {
        val reporter = new DefaultReporter
        val actualTokens: List[Token] = JawaLexer.tokenise(Left(s), reporter)
        val actualTokenTypes = actualTokens.map(_.tokenType)
        require(actualTokenTypes.last == EOF, "Last token must be EOF, but was " + actualTokens.last.tokenType)
        require(actualTokenTypes.count(_ == EOF) == 1, "There must only be one EOF token")
        require(actualTokenTypes.init == expectedTokens, "Tokens do not match. Expected " + expectedTokens + ", but was " + actualTokenTypes.init)
      }
    }

  }

}

