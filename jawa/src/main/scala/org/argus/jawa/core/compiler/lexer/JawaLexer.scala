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

import java.io._

import org.antlr.v4.runtime.{CharStreams, Token => AntlrToken}
import org.argus.jawa.core.ast.jawafile.JawaSourceFile
import org.argus.jawa.core.compiler.Antlr4PilarLexer
import org.argus.jawa.core.io.{RangePosition, Reporter, SourceFile, StringFile}

class JawaLexer(aplexer: Antlr4PilarLexer, file: SourceFile, reporter: Reporter) extends Iterator[Token] {
  val sourceFile: SourceFile = file

  private var eofTokenEmitted = false
  protected var builtToken: Token = _


  import Antlr4PilarLexer._
  protected def fetchPilarToken(): Unit = {
    val aptoken: AntlrToken = aplexer.nextToken()
    val tokenOffset = aptoken.getStartIndex
    val rawText = aptoken.getText
    val pos: RangePosition = new RangePosition(sourceFile, tokenOffset, rawText.length())
    
    val tokenType =
      aptoken.getType match {
        case T__1 =>   // )
          Tokens.RPAREN
        case T__3 =>   // else
          Tokens.ELSE
        case T__6 =>   // =>
          Tokens.ARROW
        case T__9 =>   // [
          Tokens.LBRACKET
        case T__10 =>  // :
          Tokens.COLON
        case T__13 =>  // throw
          Tokens.THROW
        case T__16 =>  // .
          Tokens.DOT
        case T__17 =>  // switch
          Tokens.SWITCH
        case T__20 =>  // if
          Tokens.IF
        case T__21 =>  // }
          Tokens.RBRACE
        case T__22 =>  // extends
          Tokens.EXTENDS_AND_IMPLEMENTS
        case T__23 =>  // goto
          Tokens.GOTO
        case T__25 =>  // ;
          Tokens.SEMI
        case T__27 =>  // procedure
          Tokens.METHOD
        case T__28 =>  // return
          Tokens.RETURN
        case T__29 =>  // true
          Tokens.TRUE
        case T__30 =>  // record
          Tokens.CLASS_OR_INTERFACE
        case T__31 =>  // catch
          Tokens.CATCH
        case T__33 =>  // then
          Tokens.THEN
        case T__35 =>  // @
          Tokens.AT
        case T__37 =>  // ]
          Tokens.RBRACKET
        case T__40 =>  // global
          Tokens.STATIC_FIELD
        case T__44 =>  // false
          Tokens.FALSE
        case T__45 =>  // ,
          Tokens.COMMA
        case T__46 =>  // (
          Tokens.LPAREN
        case T__47 =>  // null
          Tokens.NULL
        case T__48 =>  // call
          Tokens.CALL
        case T__50 =>  // =
          Tokens.EQUALS
        case T__51 =>  // ..
          Tokens.RANGE
        case T__52 =>  // {
          Tokens.LBRACE
        case T__53 =>  // new
          Tokens.NEW
        case GID =>
          Tokens.STATIC_ID
        case ID =>
          if(aptoken.getText == "fcmpl" || aptoken.getText == "dcmpl" || aptoken.getText == "fcmpg" ||
             aptoken.getText == "dcmpg" || aptoken.getText == "lcmp")
            Tokens.CMP
          else if(aptoken.getText == "constclass")
            Tokens.CONST_CLASS
          else if(aptoken.getText == "length")
            Tokens.LENGTH
          else if(aptoken.getText == "Exception")
            Tokens.EXCEPTION
          else if(aptoken.getText == "monitorenter")
            Tokens.MONITOR_ENTER
          else if(aptoken.getText == "monitorexit")
            Tokens.MONITOR_EXIT
          else if(aptoken.getText == "instanceof")
            Tokens.INSTANCE_OF
          else Tokens.ID
        case LID =>
          Tokens.LOCATION_ID
        case MSTRING
           | STRING
           =>
          Tokens.STRING_LITERAL
        case WS =>
          Tokens.WS
        case COMMENT =>
          if(rawText != "/**/" && rawText.startsWith("/**")) Tokens.DOC_COMMENT
          else Tokens.MULTILINE_COMMENT
        case LINE_COMMENT =>
          Tokens.LINE_COMMENT
        case HEX
           | DEC
           | OCT
           | BIN
           =>
          Tokens.INTEGER_LITERAL
        case FLOAT =>
          Tokens.FLOATING_POINT_LITERAL
        case CHAR =>
          Tokens.CHARACTER_LITERAL
        case AssignOP =>
          Tokens.ASSIGN_OP
        case T__49 =>  // ^
          Tokens.HAT
        case T__7      // >
           | T__8      // |
           | T__38     // <
           | CondAndOP
           | CondOrOP
           | AndOP
           | XorOP
           | OrOP
           | EqOP
           | RelOP
           | ShiftOP
           | AddOP
           | MulOP
           | UnaryOP
           =>
          Tokens.OP
        case AntlrToken.EOF =>
          Tokens.EOF
        case T__0      // typealias
           | T__2      // typedef
           | T__4      // in
           | T__5      // start
           | T__11     // expdef
           | T__12     // ...
           | T__14     // ->
           | T__15     // +>
           | T__18     // assume
           | T__19     // enum
           | T__24     // ==>
           | T__26     // <==
           | T__32     // procdef
           | T__34     // let
           | T__36     // assert
           | T__39     // extension
           | T__41     // const
           | T__42     // -!>
           | T__43     // actiondef
           | T__54     // fun
           | ErrorChar
           => 
           reporter.error(pos, "Unexpected token: " + aptoken)
           Tokens.UNKNOWN
        case _ =>
          reporter.error(pos, "Unexpected token: " + aptoken)
          Tokens.UNKNOWN
      }
    
    token(tokenType, pos, rawText)
  }
  
  /**
   * Mark the end of a token of the given type.
   */
  protected def token(tokenType: TokenType, pos: RangePosition, rawText: String) {
    builtToken = Token(tokenType, pos, rawText)
  }
  
  private[lexer] def text = aplexer.getText
  
  def next(): Token = {
    fetchPilarToken()

    if (builtToken.tokenType == Tokens.EOF)
      eofTokenEmitted = true
    builtToken
  }

  def hasNext: Boolean = !eofTokenEmitted
}

object JawaLexer {

  /**
   * Convert the given Pilar source code into a list of "raw" tokens.
   *
   * This includes whitespace and comment tokens. No NEWLINE or NEWLINES tokens are inferred. The final token
   * will be of type EOF.
   */
  def rawTokenise(source: Either[String, JawaSourceFile], reporter: Reporter): List[Token] =
    createRawLexer(source, reporter).toList

  /**
   * Create a lexer for "raw" tokens.
   *
   * @see rawTokenise
   */
  def createRawLexer(source: Either[String, SourceFile], reporter: Reporter): JawaLexer = {
    val reader = source match {
      case Left(code) => new StringReader(code)
      case Right(srcfile) => new StringReader(srcfile.code)
    }
    val input = CharStreams.fromReader(reader)
    val aplexer = new Antlr4PilarLexer(input)
    val file: SourceFile = source match {
      case Left(c) =>
        val sf = new JawaSourceFile(new StringFile(c))
        sf.code
        sf
      case Right(f) => f
    }
    makeRawLexer(aplexer, file, reporter)
  }
    
  def makeRawLexer(aplexer: Antlr4PilarLexer, file: SourceFile, reporter: Reporter): JawaLexer =
    new JawaLexer(aplexer, file, reporter)

  /**
   * Convert the given Pilar source code into a list of tokens.
   *
   * whitespace and comments are absorbed into the token they
   * precede. The final token will be of type EOF.
   *
   */
  def tokenise(source: Either[String, SourceFile], reporter: Reporter): List[Token] = {
    val rawLexer = createRawLexer(source, reporter)
    val lexer = new WhitespaceAndCommentsGrouper(rawLexer)
    lexer.toList
  }

}
