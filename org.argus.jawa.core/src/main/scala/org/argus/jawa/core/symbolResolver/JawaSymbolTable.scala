/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.symbolResolver

import org.argus.jawa.core.MethodBody
import org.sireum.pilar.ast.GlobalVarDecl
import org.sireum.pilar.symbol._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class JawaSymbolTable extends SymbolTable with SymbolTableProducer {
  st =>
  val tables = SymbolTableData()
  val tags: MArray[LocationTag] = marrayEmpty[LocationTag]
  var hasErrors = false

  val ERROR_TAG_TYPE = MarkerType(
    "org.argus.jawa.core.symbolResolver",
    None,
    "Jawa Symbol Resolution Error",
    MarkerTagSeverity.Error,
    MarkerTagPriority.Normal,
    ilist(MarkerTagKind.Problem, MarkerTagKind.Text))

  val WARNING_TAG_TYPE = MarkerType(
    "org.argus.jawa.core.symbolResolver",
    None,
    "Jawa Symbol Resolution Warning",
    MarkerTagSeverity.Warning,
    MarkerTagPriority.Normal,
    ilist(MarkerTagKind.Problem, MarkerTagKind.Text))

  def reportError(source: Option[FileResourceUri], line: Int,
                    column: Int, message: String): Unit = {
      tags += Tag.toTag(source, line, column, message, ERROR_TAG_TYPE)
      hasErrors = true
    }

  def reportWarning(fileUri: Option[String], line: Int,
                    column: Int, message: String): Unit =
    tags += Tag.toTag(fileUri, line, column, message, WARNING_TAG_TYPE)

  def reportError(source: Option[FileResourceUri], line: Int,
                  column: Int, offset: Int, length: Int,
                  message: String): Unit = {
    tags += Tag.toTag(source, line, column, offset, length, message,
      ERROR_TAG_TYPE)
    hasErrors = true
  }

  def reportWarning(fileUri: Option[String], line: Int,
                    column: Int, offset: Int, length: Int,
                    message: String): Unit =
    tags += Tag.toTag(fileUri, line, column, offset, length, message,
      WARNING_TAG_TYPE)

  val pdMap: MMap[ResourceUri, MethodBody] = mmapEmpty[ResourceUri, MethodBody]

  def globalVars: Iterable[ResourceUri] = tables.globalVarTable.keys

  def globalVar(globalUri: ResourceUri): GlobalVarDecl = tables.globalVarTable(globalUri)

  def procedures: Iterable[ResourceUri] = tables.procedureTable.keys

  def procedures(procedureUri: ResourceUri): MBuffer[ResourceUri] = tables.procedureTable(procedureUri)

  def procedureSymbolTables: Iterable[MethodBody] = pdMap.values

  def procedureSymbolTable(procedureAbsUri: ResourceUri): ProcedureSymbolTable =
    procedureSymbolTableProducer(procedureAbsUri)

  def procedureSymbolTableProducer(procedureAbsUri: ResourceUri): MethodBody = {
    assert(tables.procedureAbsTable.contains(procedureAbsUri))
    pdMap.getOrElseUpdate(procedureAbsUri, new MethodBody(procedureAbsUri, st))
  }

  def toSymbolTable: SymbolTable = this
}
