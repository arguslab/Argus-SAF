/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.pilar.symbol.ProcedureSymbolTableProducer
import org.sireum.pilar.symbol.ProcedureSymbolTableData
import org.sireum.util._
import org.sireum.pilar.ast._
import org.sireum.pilar.symbol.SymbolTable
import org.sireum.pilar.symbol.SymbolTableProducer

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class MethodBody(val procedureUri: ResourceUri, st: SymbolTable) extends ProcedureSymbolTable with ProcedureSymbolTableProducer {
  val tables = ProcedureSymbolTableData()
  var nextLocTable: CMap[ResourceUri, ResourceUri] = _
  var symbolTable: SymbolTable = st
  var symbolTableProducer: SymbolTableProducer = st.asInstanceOf[SymbolTableProducer]
  def procedure = symbolTableProducer.tables.procedureAbsTable(procedureUri)
  def typeVars: ISeq[ResourceUri] = tables.typeVarTable.keys.toList
  def params: ISeq[ResourceUri] = tables.params.toList
  def isParam(localUri: ResourceUri) = tables.params.contains(localUri)
  def locals: Iterable[ResourceUri] = tables.localVarTable.keys
  def nonParamLocals: Iterable[ResourceUri] = tables.localVarTable.keys.filterNot(isParam)
  def locations =
    tables.bodyTables match {
      case Some(bt) => procedure.body.asInstanceOf[ImplementedBody].locations
      case _        => ivectorEmpty
    }
  def typeVar(typeVarUri: ResourceUri): NameDefinition =
    tables.typeVarTable(typeVarUri)
  def param(paramUri: ResourceUri): ParamDecl =
    tables.localVarTable(paramUri).asInstanceOf[ParamDecl]
  def local(localUri: ResourceUri): LocalVarDecl =
    tables.localVarTable(localUri).asInstanceOf[LocalVarDecl]
  def location(locationIndex: Int) = locations(locationIndex)
  def location(locationUri: ResourceUri) =
    tables.bodyTables.get.locationTable(locationUri)
  def catchClauses(locationIndex: Int): Iterable[CatchClause] =
    tables.bodyTables.get.catchTable.getOrElse(locationIndex,
      Array.empty[CatchClause]: Iterable[CatchClause])

}
