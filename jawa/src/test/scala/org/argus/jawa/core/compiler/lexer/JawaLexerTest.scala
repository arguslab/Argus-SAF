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
import org.scalatest._

import scala.language.implicitConversions

class JawaLexerTest extends FlatSpec with Matchers {

  implicit def string2TestString(s: String): TestString =
    new TestString(s)

  "" producesTokens ()

  """`format`""" producesTokens ID

  "`format`;`format`" producesTokens (ID, SEMI, ID)

  "|||" producesTokens OP

  ":=" producesTokens ASSIGN_OP

  "^~" producesTokens OP

  "v0/2" producesTokens (ID, OP, INTEGER_LITERAL)

  "record" producesTokens CLASS_OR_INTERFACE

  "procedure" producesTokens METHOD

  "foo  bar   baz" producesTokens (ID, WS, ID, WS, ID)

  "  " producesTokens WS

  "// comment" producesTokens LINE_COMMENT

  "//" producesTokens LINE_COMMENT

  "foo// comment" producesTokens (ID, LINE_COMMENT)

  "foo // comment" producesTokens (ID, WS, LINE_COMMENT)

  """foo// comment
    abc//comment""" producesTokens (ID, LINE_COMMENT, WS, ID, LINE_COMMENT)

  "foo/* comment */bar" producesTokens (ID, MULTILINE_COMMENT, ID)

  "/* bar var */" producesTokens MULTILINE_COMMENT

  "/**/" producesTokens MULTILINE_COMMENT

  "/***/" producesTokens DOC_COMMENT

  "/** asdf */" producesTokens DOC_COMMENT

  "`yield`" producesTokens ID

  """"foobar"""" producesTokens STRING_LITERAL

  """`@@global`""" producesTokens STATIC_ID

  """@@global""" producesTokens STATIC_ID

  "\"\"\"f\"o\"o\"\"\"" producesTokens STRING_LITERAL

  """"\""""" producesTokens STRING_LITERAL

  "foo.bar.baz()" producesTokens (ID, DOT, ID, DOT, ID, LPAREN, RPAREN)

  ".1234" producesTokens FLOATING_POINT_LITERAL
  ".1234e2" producesTokens FLOATING_POINT_LITERAL
  ".1234e+2" producesTokens FLOATING_POINT_LITERAL
  ".1e-2" producesTokens FLOATING_POINT_LITERAL
  ".1e+2345f" producesTokens FLOATING_POINT_LITERAL
  ".1e+2345d" producesTokens FLOATING_POINT_LITERAL

  "100" producesTokens INTEGER_LITERAL
  "1" producesTokens INTEGER_LITERAL
  "1L" producesTokens INTEGER_LITERAL
  "0" producesTokens INTEGER_LITERAL
  "0L" producesTokens INTEGER_LITERAL
  "0x2345" producesTokens INTEGER_LITERAL
  "0x1" producesTokens INTEGER_LITERAL
  "0x32413L" producesTokens INTEGER_LITERAL

  "#" producesTokens LOCATION_ID
  "#L00011." producesTokens LOCATION_ID

  "0.1234" producesTokens FLOATING_POINT_LITERAL
  "0.1234e2" producesTokens FLOATING_POINT_LITERAL
  "0.1234e+2" producesTokens FLOATING_POINT_LITERAL
  "0.1e-2" producesTokens FLOATING_POINT_LITERAL
  "0.1e+2345f" producesTokens FLOATING_POINT_LITERAL
  "0.1e+2345d" producesTokens FLOATING_POINT_LITERAL

  "10e2" producesTokens FLOATING_POINT_LITERAL
  "10e+2" producesTokens FLOATING_POINT_LITERAL
  "10e-2" producesTokens FLOATING_POINT_LITERAL
  "10e+2345f" producesTokens FLOATING_POINT_LITERAL
  "10e+2345d" producesTokens FLOATING_POINT_LITERAL

  "'f'" producesTokens CHARACTER_LITERAL
  """'\n'""" producesTokens CHARACTER_LITERAL
  """'\025'""" producesTokens CHARACTER_LITERAL

  "#L0001. tokenTextBuffer:= new StringBuilder" producesTokens (LOCATION_ID, WS, ID, ASSIGN_OP, WS, NEW, WS, ID)

  "#Lx. lcmp(v0, v1);" producesTokens (LOCATION_ID, WS, CMP, LPAREN, ID, COMMA, WS, ID, RPAREN, SEMI)

  """println("bob")
println("foo")""" producesTokens (ID, LPAREN, STRING_LITERAL, RPAREN, WS, ID, LPAREN, STRING_LITERAL, RPAREN)

  "\"\\u0061\"" producesTokens STRING_LITERAL
  "\"\\u000a\"" producesTokens STRING_LITERAL


  "0X1234" producesTokens INTEGER_LITERAL


  "\"\\u001A\"" producesTokens STRING_LITERAL

  "\"\"\"\\u001A\"\"\"" producesTokens STRING_LITERAL

  "foo+\\u0061+bar" producesTokens (ID, OP, ID, OP, ID)

  "-5f.max(2)" producesTokens (FLOATING_POINT_LITERAL, DOT, ID, LPAREN, INTEGER_LITERAL, RPAREN)

  "Lexer" should "throw a lexer exception" in {
    val reporter = new DefaultReporter
    an [RuntimeException] should be thrownBy {
      JawaLexer.rawTokenise(Left("\"\"\""), reporter)
      if(reporter.hasErrors){
        reporter.problems.foreach(p => println(p.toString()))
        throw new RuntimeException
      }
    }
  }

"""
record `com.ksu.passwordPassTest.MainActivity`  @kind class @AccessFlag PUBLIC  extends `android.app.Activity` @kind class {
      `android.widget.EditText` `com.ksu.passwordPassTest.MainActivity.editText`    @AccessFlag ;
      `android.widget.Button` `com.ksu.passwordPassTest.MainActivity.passButton`    @AccessFlag ;
   }
    procedure `void` `com.ksu.passwordPassTest.MainActivity.<init>` (`com.ksu.passwordPassTest.MainActivity` v1 @kind `this`) @signature `Lcom/ksu/passwordPassTest/MainActivity;.<init>:()V` @Access `PUBLIC_CONSTRUCTOR` {
      temp ;
        v0;

#L047178.   v0:= 0I  @kind int;
#L04717a.   call temp:=  `<init>`(v1) @signature `Landroid/app/Activity;.<init>:()V` @kind direct;
#L047180.   v1.`com.ksu.passwordPassTest.MainActivity.editText`  := v0 @kind object;
#L047184.   v1.`com.ksu.passwordPassTest.MainActivity.passButton`  := v0 @kind object;
#L047188.   return @void ;

   }
""" producesTokens
  (WS, CLASS_OR_INTERFACE, WS, ID, WS, AT, ID, WS, ID, WS, AT, ID, WS, ID, WS, EXTENDS_AND_IMPLEMENTS, WS, ID, WS, AT, ID, WS, ID, WS, LBRACE,
   WS, ID, WS, ID, WS, AT, ID, WS, SEMI,
   WS, ID, WS, ID, WS, AT, ID, WS, SEMI,
   WS, RBRACE,
   WS, METHOD, WS, ID, WS, ID, WS, LPAREN, ID, WS, ID, WS, AT, ID, WS, ID, RPAREN, WS, AT, ID, WS, ID, WS, AT, ID, WS, ID, WS, LBRACE,
   WS, ID, WS, SEMI,
   WS, ID, SEMI,
   WS,
   LOCATION_ID, WS, ID, ASSIGN_OP, WS, INTEGER_LITERAL, WS, AT, ID, WS, ID, SEMI, WS,
   LOCATION_ID, WS, CALL, WS, ID, ASSIGN_OP, WS, ID, LPAREN, ID, RPAREN, WS, AT, ID, WS, ID, WS, AT, ID, WS, ID, SEMI, WS,
   LOCATION_ID, WS, ID, DOT, ID, WS, ASSIGN_OP, WS, ID, WS, AT, ID, WS, ID, SEMI, WS,
   LOCATION_ID, WS, ID, DOT, ID, WS, ASSIGN_OP, WS, ID, WS, AT, ID, WS, ID, SEMI, WS,
   LOCATION_ID, WS, RETURN, WS, AT, ID, WS, SEMI,
   WS,
   RBRACE, WS)

  class TestString(s: String) {

    def producesTokens(toks: TokenType*)() {
      check(s.stripMargin, toks.toList)
    }

    private def check(s: String, expectedTokens: List[TokenType]) {
      it should ("tokenise >>>" + s + "<<< as >>>" + expectedTokens + "<<<") in {
        val reporter = new DefaultReporter
        val actualTokens: List[Token] = JawaLexer.rawTokenise(Left(s), reporter)
        val actualTokenTypes = actualTokens.map(_.tokenType)
        assert(actualTokenTypes.last == EOF, "Last token must be EOF, but was " + actualTokens.last.tokenType)
        assert(actualTokenTypes.count(_ == EOF) == 1, "There must only be one EOF token")
        val reconstitutedSource = actualTokens.init.map(_.rawText).mkString
        assert(!reporter.hasErrors, reporter.problems)
        assert(actualTokenTypes.init == expectedTokens, "Tokens do not match. Expected " + expectedTokens + ", but was " + actualTokenTypes.init)
        assert(s == reconstitutedSource, "tokens do not partition text correctly: " + s + " vs " + reconstitutedSource)
      }
    }

  }

}
