/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization.stage

import org.sireum.util._
import java.io._

import org.json4s._
import org.json4s.native.Serialization
import org.json4s.native.Serialization.{read, write}
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.plugin.ApiMisuseResult
import org.argus.amandroid.serialization.{ApkSerializer, ContextSerializer, PTAResultSerializer, SignatureKeySerializer}
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisSimpleResult
import org.argus.jawa.core.Signature
import org.argus.jawa.core.util.MyFileUtil

object Staging {
  
  def stageApk(apk: ApkModel, outApkUri: FileResourceUri): Unit = {
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val apkRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "apk.json"))
    val oapk = new PrintWriter(apkRes)
    implicit val formats = Serialization.formats(NoTypeHints) + ApkSerializer + PTAResultSerializer
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
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "ptaresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + PTAResultSerializer + SignatureKeySerializer
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
  
  def stage(apk: ApkModel, ptaresults: IMap[Signature, PTAResult], outApkUri: FileResourceUri): Unit = {
    stageApk(apk, outApkUri)
    stagePTAResult(ptaresults, outApkUri)
  }
  
  def stageTaintAnalysisResult(tasr: TaintAnalysisSimpleResult, outApkUri: FileResourceUri): Unit = {
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "taintresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + ContextSerializer
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
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) outStageDir.mkdirs()
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "misuseresult.json"))
    val opts = new PrintWriter(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + ContextSerializer
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
  
  def recoverApk(outApkUri: FileResourceUri): ApkModel = {
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val apkRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "apk.json"))
    val rapk = new FileReader(apkRes)
    implicit val formats = Serialization.formats(NoTypeHints) + ApkSerializer
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
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "ptaresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + PTAResultSerializer + SignatureKeySerializer
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
    (recoverApk(outApkUri), recoverPTAResult(outApkUri))
  }
  
  def recoverTaintAnalysisResult(outApkUri: FileResourceUri): TaintAnalysisSimpleResult = {
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "taintresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + ContextSerializer
    try {
      val tasr = read[TaintAnalysisSimpleResult](rpts)
      tasr
    } catch {
      case e: Exception =>
        throw e
    } finally {
      rpts.close()
    }
  }
  
  def recoverAPIMisuseResult(outApkUri: FileResourceUri): ApiMisuseResult = {
    val outStageUri = MyFileUtil.appendFileName(outApkUri, "stage")
    val outStageDir = FileUtil.toFile(outStageUri)
    if(!outStageDir.exists()) throw new RuntimeException("Did not have stage folder!")
    val ptsRes = FileUtil.toFile(MyFileUtil.appendFileName(outStageUri, "misuseresult.json"))
    val rpts = new FileReader(ptsRes)
    implicit val formats = Serialization.formats(NoTypeHints) + PTAResultSerializer
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
    val stageRp = FileUtil.toFile(MyFileUtil.appendFileName(outUri, "stage_report.txt"))
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
    val stageRp = FileUtil.toFile(MyFileUtil.appendFileName(outUri, "stage_report.txt"))
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