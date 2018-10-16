/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.astselect

import scala.util.control.Exception._
import org.argus.jawa.core.compiler.lexer._
import org.argus.jawa.core.compiler.parser._
import org.argus.jawa.core.io.DefaultReporter

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object AstSelector {
  /**
   * Expands the given selection in the source to the range of the closest appropriate
   * enclosing AST element. Returns None if the source does not parse correctly, or if
   * there is no strictly larger containing AST element.
   */
  def expandSelection(source: String, initialSelection: Range): Option[Range] =
    catching(classOf[JawaParserException]).toOption {
      new AstSelector(source).expandSelection(initialSelection)
    }
}

class AstSelector(source: String) {
  val reporter = new DefaultReporter
  
  private val tokens = JawaLexer.tokenise(Left(source),reporter )
  
  private val allTokens: List[Token] = tokens.flatMap { token =>
    token.associatedWhitespaceAndComments.rawTokens :+ token
  }
  
  def expandSelection(initialSelection: Range): Option[Range] =
    expandToToken(initialSelection)
      
  /**
   * If the selection is a strict subrange of some token, expand to the entire token.
   */
  private def expandToToken(initialSelection: Range): Option[Range] =
    allTokens.find { token =>
      isSelectableToken(token) && (token.range contains initialSelection) && initialSelection.length < token.length
    }.map(_.range)

  private def isSelectableToken(token: Token) = {
    val tokenType = token.tokenType
    import tokenType._
    isLiteral || isId
  }
}
