/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.lexer

import org.argus.jawa.compiler.lexer.Tokens._

object Keywords {

  def apply(s: String): Option[TokenType] = keywords get s

  private val keywords = Map(
    "else" -> ELSE,
    "throw" -> THROW,
    "switch" -> SWITCH,
    "if" -> IF,
    "goto" -> GOTO,
    "extends" -> EXTENDS_AND_IMPLEMENTS,
    "procedure" -> METHOD,
    "true" -> TRUE,
    "return" -> RETURN,
    "record" -> CLASS_OR_INTERFACE,
    "catch" -> CATCH,
    "then" -> THEN,
    "global" -> STATIC_FIELD,
    "false" -> FALSE,
    "null" -> NULL,
    "call" -> CALL,
    "new" -> NEW)

}
