/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.astselect

import scala.util.control.Exception._
import org.argus.jawa.compiler.lexer._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.DefaultReporter

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
