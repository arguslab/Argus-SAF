/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core

import org.sireum.util._
import java.util.zip.ZipInputStream
import java.io.FileInputStream
import java.util.zip.ZipEntry

import org.argus.amandroid.alir.componentSummary.ComponentSummaryTable
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.AndroidReachingFactsAnalysisConfig
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.dataDependenceAnalysis.InterproceduralDataDependenceInfo
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.interprocedural.InterproceduralNode
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.{Global, JawaType, Reporter}
import org.sireum.alir.AlirEdge

object ApkGlobal {
  def isValidApk(nameUri: FileResourceUri): Boolean = {
    class ValidApk extends Exception
    val file = FileUtil.toFile(nameUri)
    file match {
      case dir if dir.isDirectory => false
      case _ => 
        var valid: Boolean = false
        var foundManifest: Boolean = false
        var foundDex: Boolean = false
        var archive: ZipInputStream = null
        try {
          archive = new ZipInputStream(new FileInputStream(file))
          var entry: ZipEntry = null
          entry = archive.getNextEntry
          while (entry != null) {
            val entryName = entry.getName
            if(entryName == "AndroidManifest.xml"){
              foundManifest = true
            } else if(entryName == "classes.dex"){
              foundDex = true
            }
            if(foundManifest && foundDex) {
              valid = true
              throw new ValidApk
            }
            entry = archive.getNextEntry
          }
        } catch {
          case ie: InterruptedException => throw ie
          case _: Exception =>
        } finally {
          if (archive != null)
            archive.close()
        }
        valid
    }
  }
  def isDecompilable(nameUri: FileResourceUri): Boolean = {
    class ValidJar extends Exception
    val file = FileUtil.toFile(nameUri)
    file match {
      case dir if dir.isDirectory => false
      case _ => 
        var valid: Boolean = false
        var archive: ZipInputStream = null
        try {
          archive = new ZipInputStream(new FileInputStream(file))
          var entry: ZipEntry = null
          entry = archive.getNextEntry
          while (entry != null) {
            val entryName = entry.getName
            if(entryName == "classes.dex"){
              valid = true
              throw new ValidJar
            }
            entry = archive.getNextEntry
          }
        } catch {
          case ie: InterruptedException => throw ie
          case _: Exception =>
        } finally {
          if (archive != null)
            archive.close()
        }
        valid
    }
  }
}

case class InvalidApk(fileUri: FileResourceUri) extends Exception

/**
 * this is an object, which hold information of apps. e.g. components, intent-filter database, etc.
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a> 
 */
class ApkGlobal(val model: ApkModel, reporter: Reporter) extends Global(model.nameUri, reporter) {
  import ApkGlobal._

  require(isValidApk(model.nameUri), throw InvalidApk(model.nameUri))
  setJavaLib(AndroidGlobalConfig.settings.lib_files)

  def nameUri: FileResourceUri = model.nameUri

  def resolveEnvInGlobal(): Unit = {
    model.getEnvMap.foreach {
      case (_, (sig, code)) =>
        resolveMethodCode(sig, code)
    }
  }

  private val idfgResults: MMap[JawaType, InterproceduralDataFlowGraph] = mmapEmpty

  def addIDFG(key: JawaType, idfg: InterproceduralDataFlowGraph): Unit = this.synchronized(this.idfgResults += (key -> idfg))
  def hasIDFG(key: JawaType): Boolean = this.synchronized(this.idfgResults.contains(key))
  def getIDFG(key: JawaType): Option[InterproceduralDataFlowGraph] = this.synchronized(this.idfgResults.get(key))
  def getIDFGs: Map[JawaType, InterproceduralDataFlowGraph] = this.idfgResults.toMap

  private val iddaResults: MMap[JawaType, InterproceduralDataDependenceInfo] = mmapEmpty

  def addIDDG(key: JawaType, iddi: InterproceduralDataDependenceInfo): Unit = this.synchronized(this.iddaResults += (key -> iddi))
  def hasIDDG(key: JawaType): Boolean = this.iddaResults.contains(key)
  def getIDDG(key: JawaType): Option[InterproceduralDataDependenceInfo] = this.synchronized(this.iddaResults.get(key))
  def getIDDGs: Map[JawaType, InterproceduralDataDependenceInfo] = this.iddaResults.toMap

  private val summaryTables: MMap[JawaType, ComponentSummaryTable] = mmapEmpty

  def addSummaryTable(key: JawaType, summary: ComponentSummaryTable): Unit = this.synchronized(this.summaryTables += (key -> summary))
  def hasSummaryTable(key: JawaType): Boolean = this.summaryTables.contains(key)
  def getSummaryTable(key: JawaType): Option[ComponentSummaryTable] = this.synchronized(this.summaryTables.get(key))
  def getSummaryTables: Map[JawaType, ComponentSummaryTable] = this.summaryTables.toMap

  private val apkTaintResult: MMap[FileResourceUri, Any] = mmapEmpty

  def addTaintAnalysisResult[N <: InterproceduralNode, E <: AlirEdge[N]](fileUri: FileResourceUri, tar: TaintAnalysisResult[N, E]): Unit = this.synchronized(this.apkTaintResult(fileUri) = tar)
  def hasTaintAnalysisResult(fileUri: FileResourceUri): Boolean = this.apkTaintResult.contains(fileUri)
  def getTaintAnalysisResult[N <: InterproceduralNode, E <: AlirEdge[N]](fileUri: FileResourceUri): Option[TaintAnalysisResult[N, E]] = this.apkTaintResult.get(fileUri).map(_.asInstanceOf[TaintAnalysisResult[N, E]])


  override def reset(removeCode: Boolean = true): Unit = {
    super.reset(removeCode)
    model.reset()
    this.idfgResults.clear()
    this.iddaResults.clear()
    this.summaryTables.clear()
    this.apkTaintResult.clear()
  }

  override def toString: String = FileUtil.toFile(nameUri).getName
}
