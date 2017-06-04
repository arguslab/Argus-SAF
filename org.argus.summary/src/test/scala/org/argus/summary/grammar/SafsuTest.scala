/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.summary.grammar

import java.io.StringReader

import org.antlr.v4.runtime._
import org.antlr.v4.runtime.misc.ParseCancellationException
import org.scalatest.{FlatSpec, Matchers}

import collection.JavaConverters._
import scala.language.implicitConversions

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class SafsuTest extends FlatSpec with Matchers {
  import SafsuLexer._

  implicit def string2TestString(s: String): TestString =
    new TestString(s)

  // T__0 = 1 -- ':'
  // T__1 = 2 -- ';'
  // T__2 = 3 -- '='
  // T__3 = 4 -- 'arg'
  // T__4 = 5 -- '.'
  // T__5 = 6 -- '@@'
  // T__6 = 7 -- '@'
  // T__7 = 8 -- 'ret'
  // UID = 9
  // ID = 10
  // Digits = 11
  // WS = 12
  // COMMENT = 13
  // LINE_COMMENT=14

  "`Lcom/my/Class;.do:()V`" producesTokens UID
  "arg:1" producesTokens (T__3, T__0, Digits)
  "arg:1.field.field2" producesTokens (T__3, T__0, Digits, T__4, ID, T__4, ID)
  "ret" producesTokens T__7
  "@@com.my.Class.Global" producesTokens (T__5, ID, T__4, ID, T__4, ID, T__4, ID)
  "com.my.Class" producesTokens (ID, T__4, ID, T__4, ID)
  "com.my.Class@L1005" producesTokens (ID, T__4, ID, T__4, ID, T__6, ID)
  "arg:1=arg:2" producesTokens (T__3, T__0, Digits, T__2, T__3, T__0, Digits)
  "arg:1=com.my.Class@L1005" producesTokens (T__3, T__0, Digits, T__2, ID, T__4, ID, T__4, ID, T__6, ID)
  "`Lcom/my/Class;.do:(LO1;LO2;)V`:arg:1=arg:2;" producesTokens (UID, T__0, T__3, T__0, Digits, T__2, T__3, T__0, Digits, T__1)
  """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
    |  arg:1=arg:2
    |  ret=arg:1.field
    |;
  """.stripMargin producesTokens (
    UID, T__0, WS,
    T__3, T__0, Digits, T__2, T__3, T__0, Digits, WS,
    T__7, T__2, T__3, T__0, Digits, T__4, ID, WS,
    T__1, WS)
  """/* block comment
    | */
  """.stripMargin producesTokens (COMMENT, WS)
  """/** Doc comment
    |  */
  """.stripMargin producesTokens (COMMENT, WS)
  """// line comment""" producesTokens LINE_COMMENT

  class TestString(s: String) {

    def producesTokens(tokens: Int*)() {
      check(s.stripMargin, tokens.toList)
    }

    private def check(s: String, expectedTokens: List[Int]) {
      it should ("tokenize >>>" + s + "<<< as >>>" + expectedTokens + "<<<") in {
        val reader = new StringReader(s)
        val input = CharStreams.fromReader(reader)
        val lexer = new SafsuLexer(input)
        val actualTokens: List[_ <: Token] = lexer.getAllTokens.asScala.toList
        val actualTokenTypes = actualTokens.map(_.getType)
        require(actualTokenTypes == expectedTokens, "Tokens do not match. Expected " + expectedTokens + ", but was " + actualTokenTypes)
      }
    }

  }

  "Parser" should "not throw a parse exception on complete program" in {
    parse(
      """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
        |  arg:1=arg:2
        |  ret=arg:1.field
        |;
      """.stripMargin)
  }

  "Parser" should "throw a parse exception on bad program" in {
    an [RecognitionException] should be thrownBy {
      parse(
        """`Lcom/my/Class;.do:(LO1;LO2;)LO3;`:
          |  arg:1=
          |  ret=arg:1.field
          |;
        """.stripMargin)
    }
  }

  def parse(code: String): Unit = {
    val reader = new StringReader(code)
    val input = CharStreams.fromReader(reader)
    val lexer = new SafsuLexer(input)
    val tokens = new CommonTokenStream(lexer)
    val parser = new SafsuParser(tokens)
    parser.setErrorHandler(new BailErrorStrategy)
    try {
      parser.summaryFile()
    } catch {
      case pce: ParseCancellationException =>
        throw pce.getCause
    }
  }
}