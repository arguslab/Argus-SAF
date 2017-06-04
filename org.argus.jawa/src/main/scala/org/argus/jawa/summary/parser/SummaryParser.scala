/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.parser

import java.io.StringReader

import org.antlr.v4.runtime.misc.ParseCancellationException
import org.antlr.v4.runtime.{BailErrorStrategy, CharStreams, CommonTokenStream, RecognitionException}
import org.argus.jawa.summary.rule.SummaryFile
import org.argus.jawa.summary.grammar.{SafsuLexer, SafsuParser}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object SummaryParser {
  def apply(source: String): SummaryFile =
    parse(source)

  @throws[RecognitionException]
  def parse(source: String): SummaryFile = {
    val reader = new StringReader(source)
    val input = CharStreams.fromReader(reader)
    val lexer = new SafsuLexer(input)
    val cts = new CommonTokenStream(lexer)
    val parser = new SafsuParser(cts)
    parser.setErrorHandler(new BailErrorStrategy)
    try {
      SummaryParserVisitor(parser.summaryFile())
    } catch {
      case pce: ParseCancellationException =>
        throw pce.getCause
    }

  }
}
