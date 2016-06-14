/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.symbolResolver

import org.sireum.pilar.ast._
import org.sireum.util._
import org.sireum.pilar.symbol._

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object JawaSymbolTableBuilder {
  def apply(models: ISeq[Model],
            stpConstructor: Unit => SymbolTableProducer,
            parallel: Boolean) =
    buildSymbolTable(models, stpConstructor, parallel)

  def apply[P <: SymbolTableProducer] //
  (stp: SymbolTableProducer, stModels: ISeq[Model],
   changedOrDeletedModelFiles: Set[FileResourceUri],
   changedOrAddedModels: ISeq[Model],
   stpConstructor: Unit => P,
   parallel: Boolean) =
    fixSymbolTable(stp, stModels, changedOrDeletedModelFiles,
      changedOrAddedModels, stpConstructor, parallel)

  def minePackageElements[P <: SymbolTableProducer] //
  (models: ISeq[Model], stpConstructor: Unit => P,
   parallel: Boolean): SymbolTableProducer = {
    if (models.isEmpty) return stpConstructor()

    val ms: GenSeq[Model] = if (parallel) models.par else models
    ms.map { model =>
      val stp = stpConstructor()
      new H.PackageElementMiner(stp).packageElementMiner(model)
      val tables = stp.tables
      model.sourceURI.foreach { fileUri =>
        val set = msetEmpty[ResourceUri]
        set ++= tables.constTable.keys
        set ++= tables.constElementTable.keys
        set ++= tables.enumTable.keys
        set ++= tables.enumElementTable.keys
        set ++= tables.extensionTable.keys
        set ++= tables.extensionElementTable.keys
        set ++= tables.funTable.keys
        set ++= tables.globalVarTable.keys
        set ++= tables.procedureTable.keys
        set ++= tables.procedureAbsTable.keys
        set ++= tables.recordTable.keys
        set ++= tables.attributeTable.keys
        set ++= tables.typeVarTable.keys
        set ++= tables.typeAliasTable.keys
        set ++= tables.vsetTable.keys
        tables.declaredSymbols(fileUri) = set
      }
      stp
    }.reduce(H.combine)
  }
  
  def buildProcedureSymbolTables(stp: SymbolTableProducer, parallel: Boolean): Unit = {
    val procedures = stp.tables.procedureAbsTable.keys.toSeq
    doBuildPST(stp, procedures, parallel)
  }
  
  def fixProcedureSymbolTables(stp: SymbolTableProducer, newProcedures: Seq[ResourceUri], parallel: Boolean): Unit = {
    doBuildPST(stp, newProcedures, parallel)
  }
  
  private def doBuildPST(stp: SymbolTableProducer, procedures: Seq[ResourceUri], parallel: Boolean): Unit = {
    val col: GenSeq[ResourceUri] = if (false) procedures.par else procedures
    col.map { procedureUri =>
      val pstp = stp.procedureSymbolTableProducer(procedureUri)
      val pd = stp.tables.procedureAbsTable(procedureUri)
      pd.body match {
        case body: ImplementedBody =>
          pstp.tables.bodyTables = Some(BodySymbolTableData())
        case body: EmptyBody =>
      }
      val pmr = new H.ProcedureMinerResolver(pstp)
      pmr.procMiner(pd)
      pmr.procResolver(pd)
    }
  }
  
  def buildSymbolTable(models: ISeq[Model],
                       stpConstructor: Unit => SymbolTableProducer,
                       parallel: Boolean) = {
    val stp = minePackageElements(models, stpConstructor, parallel)
    resolvePackageElements(models, stp, parallel)
    buildProcedureSymbolTables(stp, parallel)
    stp.toSymbolTable
  }
  
  def resolvePackageElements(models: ISeq[Model], stp: SymbolTableProducer,
                             parallel: Boolean): Unit = {
    if (models.isEmpty) return

    val ms: GenSeq[Model] = if (parallel) models.par else models

    val dependencies = ms.map { model =>
      val per = new H.PackageElementResolver(stp)
      per.packageElementResolver(model)
      per.dependency
    }
    dependencies.foldLeft(stp.tables.dependency)(H.combineMap)
  }
  
  def fixSymbolTable[P <: SymbolTableProducer] //
  (stp: SymbolTableProducer, stModels: ISeq[Model],
   changedOrDeletedModelFiles: Set[FileResourceUri],
   changedOrAddedModels: ISeq[Model],
   stpConstructor: Unit => P,
   parallel: Boolean) = {

    val models = mlistEmpty[Model]
    stModels.foreach { m =>
      m.sourceURI match {
        case Some(uri) =>
          if (changedOrDeletedModelFiles.contains(uri))
            H.tearDown(stp.tables, m)
          else
            models += m
        case _ =>
      }
    }
    val newStp = minePackageElements(changedOrAddedModels, stpConstructor, parallel)
    H.combine(stp, newStp)
    models ++= changedOrAddedModels
    resolvePackageElements(models.toList, stp, parallel)
    
    fixProcedureSymbolTables(stp, newStp.tables.procedureAbsTable.keySet.toSeq, parallel)
    (stp.toSymbolTable, newStp.tables.procedureAbsTable.keySet)
  }
}
