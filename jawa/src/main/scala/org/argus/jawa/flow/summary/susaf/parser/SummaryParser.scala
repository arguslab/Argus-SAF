/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.susaf.parser

import java.io.StringReader

import org.antlr.v4.runtime.misc.ParseCancellationException
import org.antlr.v4.runtime.{BailErrorStrategy, CharStreams, CommonTokenStream, NoViableAltException}
import org.argus.jawa.flow.summary.susaf.rule.HeapSummaryFile
import org.argus.jawa.flow.summary.grammar.{SafsuLexer, SafsuParser}

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