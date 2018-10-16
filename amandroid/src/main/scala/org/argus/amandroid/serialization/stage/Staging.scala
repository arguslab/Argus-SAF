/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization.stage

import org.argus.jawa.core.util._
import java.io._

import org.json4s._
import org.json4s.native.Serialization
import org.json4s.native.Serialization.{read, write}
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.plugin.ApiMisuseResult
import org.argus.amandroid.serialization.{ApkModelSerializer, ContextSerializer, PTAResultSerializer, SignatureKeySerializer}
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.FileUtil

object Staging {
  
  def stageApkModel(apk: ApkModel): Unit = {
    val outStageUri = FileUtil.appendFileName(apk.layout.outputSrcUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val apkRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "apk.json"))
    val oapk = new PrintWriter(apkRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ApkModelSerializer + PTAResultSerializer
    try {
      write(apk, oapk)
    } catch {
      case e: Exception =>
        apkRes.delete()
        throw e
    } finally {
      oapk.flush()
      oapk.close()
    }
  }
  
  def stagePTAResult(ptaresults: IMap[Signature, PTAResult], outApkUri: FileResourceUri): Unit = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "ptaresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + PTAResultSerializer + SignatureKeySerializer
    try {
      write(ptaresults, opts)
    } catch {
      case e: Exception =>
        ptsRes.delete()
        throw e
    } finally {
      opts.flush()
      opts.close()
    }
  }
  
  def stage(apk: ApkModel, ptaresults: IMap[Signature, PTAResult]): Unit = {
    stageApkModel(apk)
    stagePTAResult(ptaresults, apk.layout.outputSrcUri)
  }
  
  def stageTaintAnalysisResult(tasr: TaintAnalysisResult, outApkUri: FileResourceUri): Unit = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "taintresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ContextSerializer
    try {
      write(tasr, opts)
    } catch {
      case e: Exception =>
        ptsRes.delete()
        throw e
    } finally {
      opts.flush()
      opts.close()
    }
  }
  
  def stageAPIMisuseResult(amr: ApiMisuseResult, outApkUri: FileResourceUri): Unit = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "misuseresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ContextSerializer
    try {
      write(amr, opts)
    } catch {
      case e: Exception =>
        ptsRes.delete()
        throw e
    } finally {
      opts.flush()
      opts.close()
    }
  }
  
  def recoverApkModel(outApkUri: FileResourceUri): ApkModel = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val apkRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "apk.json"))
    val rapk = new FileReader(apkRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ApkModelSerializer
    try {
      val apk = read[ApkModel](rapk)
      apk
    } catch {
      case e: Exception =>
        throw e
    } finally {
      rapk.close()
    }
  }
  
  def recoverPTAResult(outApkUri: FileResourceUri): IMap[Signature, PTAResult] = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "ptaresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + PTAResultSerializer + SignatureKeySerializer
    try {
      val ptaresults = read[IMap[Signature, PTAResult]](rpts)
      ptaresults
    } catch {
      case e: Exception =>
        throw e
    } finally {
      rpts.close()
    }
  }
  
  def recoverStage(outApkUri: FileResourceUri): (ApkModel, IMap[Signature, PTAResult]) = {
    (recoverApkModel(outApkUri), recoverPTAResult(outApkUri))
  }
  
  def recoverTaintAnalysisResult(outApkUri: FileResourceUri): TaintAnalysisResult = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "taintresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + ContextSerializer
    try {
      val tasr = read[TaintAnalysisResult](rpts)
      tasr
    } catch {
      case e: Exception =>
        throw e
    } finally {
      rpts.close()
    }
  }
  
  def recoverAPIMisuseResult(outApkUri: FileResourceUri): ApiMisuseResult = {
    val outStageUri = FileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "misuseresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints) + PTAResultSerializer
    try {
      val amr = read[ApiMisuseResult](rpts)
      amr
    } catch {
      case e: Exception =>
        throw e
    } finally {
      rpts.close()
    }
  }
  
  def isStageAvailable(outApkUri: FileResourceUri): Boolean = {
    val outStageDir = new File(FileUtil.toFile(outApkUri), "stage")
    outStageDir.exists() && new File(outStageDir, "apk.json").exists() && new File(outStageDir, "ptaresult.json").exists()
  }

  def hasStage(outUri: FileResourceUri, apkName: String): Boolean = {
    val stageRp = FileUtil.toFile(FileUtil.appendFileName(outUri, "stage_report.txt"))
    if(stageRp.exists()) {
      val br = new BufferedReader(new FileReader(stageRp))
      var line = br.readLine()
      var found = false
      while (line != null && line != apkName) {
        line = br.readLine()
        if (line == apkName) found = true
      }
      br.close()
      found
    } else false
  }

  def stageReport(outUri: FileResourceUri, apkName: String): Unit = {
    val stageRp = FileUtil.toFile(FileUtil.appendFileName(outUri, "stage_report.txt"))
    this.synchronized {
      val writer = new FileWriter(stageRp, true)
      try {
        writer.write(apkName + "\n")
      } catch {
        case e: Exception =>
          throw e
      } finally {
        writer.close()
      }
    }
  }
}