/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.server

import java.io.{BufferedOutputStream, ByteArrayOutputStream, File, FileOutputStream}

import com.google.common.hash.{Hashing, HashingOutputStream}
import io.grpc.stub.StreamObserver
import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidSourceAndSinkManager, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.DefaultDecompilerSettings
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.io.{MsgLevel, PrintReporter, Reporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.ICFGEntryNode
import org.argus.jawa.flow.summary.store.{TSTaintPath, TaintStore}
import org.argus.jawa.flow.summary.susaf.rule.HeapSummary
import org.argus.jawa.flow.summary.wu.TaintSummary
import org.argus.jawa.flow.summary.{SummaryProvider, SummaryToProto, summary}
import org.argus.jawa.flow.taintAnalysis._
import org.argus.jnsaf.analysis.{JNISourceAndSinkManager, NativeMethodHandler}
import org.argus.jnsaf.client.NativeDroidClient
import org.argus.jnsaf.server.jnsaf_grpc._
import org.argus.jnsaf.taint.JNTaintAnalysis

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}
import scala.language.postfixOps

object JNSafServer extends GrpcServer {
  def TITLE = "JNSafService"

  def apply(outputPath: String, port: Int, nativedroid_address: String, nativedroid_port: Int): Unit = {
    val reporter = new PrintReporter(MsgLevel.INFO)
    val dir_uri = FileUtil.toUri(outputPath)
    val ssd = JNSafGrpc.bindService(new JNSafService(dir_uri, nativedroid_address, nativedroid_port, reporter), ExecutionContext.global)
    runServer(ssd, port)
  }

  class JNSafService(dir_uri: FileResourceUri, nativedroid_address: String, nativedroid_port: Int, reporter: Reporter) extends JNSafGrpc.JNSaf {
    val dir: File = FileUtil.toFile(dir_uri)
    if (!dir.exists()) {
      dir.mkdirs()
    }
    val map: MMap[String, FileResourceUri] = mmapEmpty
    val yard = new ApkYard(reporter)
    val summaries: MMap[String, SummaryProvider] = mmapEmpty
    val ssms: MMap[String, JNISourceAndSinkManager] = mmapEmpty
    val cbas: MMap[String, ComponentBasedAnalysis] = mmapEmpty

    def loadAPK(responseObserver: StreamObserver[LoadAPKResponse]): StreamObserver[LoadAPKRequest] = {
      reporter.echo(TITLE,"Server loadAPK")
      val byteStream = new ByteArrayOutputStream
      val sha256 = new HashingOutputStream(Hashing.sha256(), byteStream)
      new StreamObserver[LoadAPKRequest] {
        def onNext(request: LoadAPKRequest): Unit = {
          request.buffer.writeTo(sha256)
        }

        def onError(t: Throwable): Unit = {
          reporter.echo(TITLE,"Client LoadBinaryResponse onError")
          responseObserver.onError(t)
        }

        def onCompleted(): Unit = {
          sha256.flush()
          val apk_digest = sha256.hash().toString
          val file_uri = FileUtil.toUri(new File(dir, apk_digest + ".apk"))
          val outputUri = FileUtil.toUri(new File(dir, apk_digest))
          map(apk_digest) = file_uri
          val buffer = new BufferedOutputStream(new FileOutputStream(FileUtil.toFile(file_uri)))
          byteStream.writeTo(buffer)
          buffer.flush()
          yard.loadApk(
            file_uri, new DefaultDecompilerSettings(outputUri, reporter),
            collectInfo = true, resolveCallBack = true, guessAppPackages = true)
          responseObserver.onNext(LoadAPKResponse(apkDigest = apk_digest, length = byteStream.size()))
          responseObserver.onCompleted()
        }
      }
    }

    private def performTaint(apkDigest: String, algo: TaintAnalysisRequest.Algorithm): Option[TaintAnalysisResult] = {
      var result: Option[TaintAnalysisResult] = None
      map.get(apkDigest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              if(algo.isBottomUp) {
                TimeUtil.timed("TaintAnalysis Running Time", reporter) {
                  try {
                    val client = new NativeDroidClient(nativedroid_address, nativedroid_port, apkDigest, reporter)
                    val handler = new NativeMethodHandler(client)
                    val ssm: AndroidSourceAndSinkManager = ssms.getOrElseUpdate(apkDigest, new JNISourceAndSinkManager(AndroidGlobalConfig.settings.sas_file))
                    val provider: SummaryProvider = summaries.getOrElseUpdate(apkDigest, new AndroidSummaryProvider(apk))
                    val cba: ComponentBasedAnalysis = cbas.getOrElseUpdate(apkDigest, new ComponentBasedAnalysis(yard))
                    val jntaint = new JNTaintAnalysis(yard, apk, handler, ssm, provider, cba, reporter, 3)
                    result = Some(jntaint.process)
                  } catch {
                    case e: Throwable =>
                      e.printStackTrace()
                  }
                }
              } else if(algo.isComponentBased) {
                ComponentBasedAnalysis.prepare(Set(apk))(AndroidGlobalConfig.settings.timeout minutes)
                val cba = new ComponentBasedAnalysis(yard)
                cba.phase1(Set(apk))
                val iddResult = cba.phase2(Set(apk))
                val ssm = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)
                result = cba.phase3(iddResult, ssm)
              }
            case None =>
          }
        case None =>
      }
      result
    }

    private def performTaint(apkDigest: String, component: JawaType, eps: ISet[Signature], depth: Int): Unit = {
      map.get(apkDigest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              try {
                val client = new NativeDroidClient(nativedroid_address, nativedroid_port, apkDigest, reporter)
                val handler = new NativeMethodHandler(client)
                val ssm: AndroidSourceAndSinkManager = ssms.getOrElseUpdate(apkDigest, new JNISourceAndSinkManager(AndroidGlobalConfig.settings.sas_file))
                val provider: SummaryProvider = summaries.getOrElseUpdate(apkDigest, new AndroidSummaryProvider(apk))
                val cba: ComponentBasedAnalysis = cbas.getOrElseUpdate(apkDigest, new ComponentBasedAnalysis(yard))
                val jntaint = new JNTaintAnalysis(yard, apk, handler, ssm, provider, cba, reporter, depth)
                jntaint.process(component, eps)
              } catch {
                case e: Throwable =>
                  e.printStackTrace()
              }
            case None =>
          }
        case None =>
      }
    }

    def taintAnalysis(request: TaintAnalysisRequest): Future[TaintAnalysisResponse] = {
      reporter.echo(TITLE,"Server taintAnalysis")
      val taintResult = performTaint(request.apkDigest, request.algo)
      val response = TaintAnalysisResponse(taintResult.map(_.toPb))
      reporter.echo(TITLE, response.toProtoString)
      Future.successful(response)
    }

    def getSummary(request: GetSummaryRequest): Future[GetSummaryResponse] = {
      reporter.echo(TITLE,s"Server getSummary for ${request.signature}")
      summaries.get(request.apkDigest) match {
        case Some(provider) =>
          if (!Signature.isValidSignature(request.signature)) {
            Future.successful(GetSummaryResponse())
          }
          val sig = new Signature(request.signature)
          var summaries = provider.getSummaryManager.getSummaries(sig)
          if(summaries.isEmpty && request.gen) {
            performTaint(request.apkDigest, new JawaType(request.componentName), Set(sig), request.depth - 1)
            summaries = provider.getSummaryManager.getSummaries(sig)
          }
          var heapSummary: Option[summary.HeapSummary] = None
          var taintResult: Option[String] = None
          summaries.foreach {
            case heap: HeapSummary =>
              heapSummary = Some(SummaryToProto.toProto(heap))
            case taint: TaintSummary =>
              taintResult = Some(taint.toString)
            case _ =>
          }
          val response = GetSummaryResponse(heapSummary = heapSummary, taintResult = taintResult.getOrElse(""))
          reporter.echo(TITLE, response.toProtoString)
          Future.successful(response)
        case None => Future.failed(new RuntimeException(s"Could not load SummaryManager for apk digest: ${request.apkDigest}"))
      }
    }

    def registerICC(request: RegisterICCRequest): Future[RegisterICCResponse] = {
      reporter.echo(TITLE,s"Server registerICC ${request.toProtoString}")
      val signature = new Signature(request.signature)
      this.ssms.get(request.apkDigest) match {
        case Some(ssm) =>
          ssm.addCustomSink("ICC", signature, request.sourceArgs.toSet, Set("ICC_SINK"))
        case None =>
      }
      if(request.targetComponentName.nonEmpty) {
        this.cbas.get(request.apkDigest) match {
          case Some(cba) =>
            cba.customICCMap.getOrElseUpdate(signature, msetEmpty) += request.targetComponentName
          case None =>
        }
      }
      Future.successful(RegisterICCResponse(status = true))
    }

    def registerTaint(request: RegisterTaintRequest): Future[RegisterTaintResponse] = {
      reporter.echo(TITLE,s"Server registerTaint ${request.toProtoString}")
      val signature = new Signature(request.signature)
      val apkDigest = request.apkDigest
      val context = new Context(apkDigest)
      context.setContext(signature, signature.signature)
      val node = TaintNode(ICFGEntryNode(context), None)
      val source = TaintSource(node, TypeTaintDescriptor(signature.signature, None, request.sourceKind))
      val sink = TaintSink(node, TypeTaintDescriptor(signature.signature, None, request.sinkKind))
      val path = TSTaintPath(source, sink)
      path.path = List(node)
      val store = new TaintStore
      store.addTaintPath(path)
      map.get(apkDigest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              apk.addComponentTaintAnalysisResult(signature.getClassType, store)
            case None =>
          }
        case None =>
      }
      Future.successful(RegisterTaintResponse(status = true))
    }
  }
}
