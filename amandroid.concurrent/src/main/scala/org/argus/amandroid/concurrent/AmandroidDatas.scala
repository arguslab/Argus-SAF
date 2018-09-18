/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.concurrent

import org.argus.amandroid.core.decompile.DecompileLayout
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

import scala.concurrent.duration.Duration

trait AmandroidData
trait Success
trait Failure

// AmandroidSupervisorActor's input
case class AnalysisSpec(fileUri: FileResourceUri, outputUri: FileResourceUri, dpsuri: Option[FileResourceUri], removeSupportGen: Boolean, forceDelete: Boolean) extends AmandroidData

// DecompileActor's input
case class DecompileData(fileUri: FileResourceUri, outputUri: FileResourceUri, dpsuri: Option[FileResourceUri], removeSupportGen: Boolean, forceDelete: Boolean, timeout: Duration) extends AmandroidData
// DecompileActor's result
trait DecompilerResult extends AmandroidData {
  def fileUri: FileResourceUri
}
case class DecompileSuccResult(fileUri: FileResourceUri, layout: DecompileLayout) extends DecompilerResult with Success
case class DecompileFailResult(fileUri: FileResourceUri, e: Throwable) extends DecompilerResult with Failure

// ApkInfoCollectActor's input
case class ApkInfoCollectData(fileUri: FileResourceUri, layout: DecompileLayout, timeout: Duration) extends DecompilerResult
// ApkInfoCollectActor's result
trait ApkInfoCollectResult extends AmandroidData {
  def fileUri: FileResourceUri
}
case class ApkInfoCollectSuccResult(model: ApkModel) extends ApkInfoCollectResult with Success {
  def fileUri: FileResourceUri = model.nameUri
}
case class ApkInfoCollectFailResult(fileUri: FileResourceUri, e: Exception) extends ApkInfoCollectResult with Failure

// PointsToAnalysisActor's input
case class PointsToAnalysisData(model: ApkModel, algos: PTAAlgorithms.Value, stage: Boolean, timeoutForeachComponent: Duration) extends AmandroidData
// PointsToAnalysisActor's result
trait PointsToAnalysisResult extends AmandroidData {
  def fileUri: FileResourceUri
  def time: Long
  def componentNum: Int
}
case class PointsToAnalysisSuccResult(model: ApkModel, time: Long, componentNum: Int, ptaresults: IMap[Signature, PTAResult]) extends PointsToAnalysisResult with Success {
  def fileUri: FileResourceUri = model.nameUri
}
case class PointsToAnalysisSuccStageResult(fileUri: FileResourceUri, time: Long, componentNum: Int, outApkUri: FileResourceUri) extends PointsToAnalysisResult with Success
case class PointsToAnalysisFailResult(fileUri: FileResourceUri, time: Long, componentNum: Int, e: Exception) extends PointsToAnalysisResult with Failure

// SecurityEngineActor's input
case class SecurityEngineData(ptar: PointsToAnalysisResult with Success, spec: SecSpec)
// SecurityEngineActor's result
trait SecurityEngineResult extends AmandroidData {
  def fileUri: FileResourceUri
}
case class SecurityEngineSuccResult(fileUri: FileResourceUri, sr: Option[SecResult]) extends SecurityEngineResult with Success
case class SecurityEngineFailResult(fileUri: FileResourceUri, e: Exception) extends SecurityEngineResult with Failure