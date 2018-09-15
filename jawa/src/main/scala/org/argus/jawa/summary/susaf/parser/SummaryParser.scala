/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.susaf.parser

import java.io.StringReader

import org.antlr.v4.runtime.misc.ParseCancellationException
import org.antlr.v4.runtime.{BailErrorStrategy, CharStreams, CommonTokenStream, NoViableAltException}
import org.argus.jawa.summary.susaf.rule.HeapSummaryFile
import org.argus.jawa.summary.grammar.{SafsuLexer, SafsuParser}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object SummaryParser {
  def apply(source: String): HeapSummaryFile =
    parse(source)

  @throws[SummaryParserException]
  def parse(source: String): HeapSummaryFile = {
    val reader = new StringReader(source)
    val input = CharStreams.fromReader(reader)
    val lexer = new SafsuLexer(input)
    val cts = new CommonTokenStream(lexer)
    val parser = new SafsuParser(cts)
    parser.setErrorHandler(new BailErrorStrategy)
    try {
      SummaryParserVisitor(parser.summaryFile())
    } catch {
      case oie: IndexOutOfBoundsException =>
        throw SummaryParserException(oie)
      case nvae: NoViableAltException =>
        throw SummaryParserException(nvae)
      case pce: ParseCancellationException =>
        throw SummaryParserException(pce.getCause)
    }
  }
}

case class SummaryParserException(cause: Throwable) extends Exception(cause.getMessage)