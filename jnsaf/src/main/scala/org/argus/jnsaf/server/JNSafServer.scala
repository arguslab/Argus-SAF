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
import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.decompile.DefaultDecompilerSettings
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.{MsgLevel, PrintReporter, Reporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.susaf.rule.HeapSummary
import org.argus.jawa.flow.summary.wu.TaintSummary
import org.argus.jawa.flow.summary.{SummaryProvider, SummaryToProto, summary}
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jnsaf.analysis.NativeMethodHandler
import org.argus.jnsaf.client.NativeDroidClient
import org.argus.jnsaf.server.jnsaf_grpc._
import org.argus.jnsaf.taint.JNTaintAnalysis

import scala.concurrent.{ExecutionContext, Future}

object JNSafServer extends GrpcServer {
  def TITLE = "JNSafService"

  class JNSafService(dir_uri: FileResourceUri, reporter: Reporter) extends JNSafGrpc.JNSaf {
    val dir: File = FileUtil.toFile(dir_uri)
    if (!dir.exists()) {
      dir.mkdirs()
    }
    val map: MMap[String, FileResourceUri] = mmapEmpty
    val yard = new ApkYard(reporter)
    val summaries: MMap[String, SummaryProvider] = mmapEmpty

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

    private def performTaint(apkDigest: String): Option[TaintAnalysisResult] = {
      var result: Option[TaintAnalysisResult] = None
      map.get(apkDigest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              TimeUtil.timed("TaintAnalysis Running Time", reporter) {
                try {
                  val client = new NativeDroidClient("localhost", 50051, apkDigest, reporter)
                  val handler = new NativeMethodHandler(client)
                  val provider: SummaryProvider = summaries.getOrElseUpdate(apkDigest, new AndroidSummaryProvider(apk))
                  val jntaint = new JNTaintAnalysis(yard, apk, handler, provider, reporter, 3)
                  result = jntaint.process
                } catch {
                  case e: Throwable =>
                    e.printStackTrace()
                }
              }
            case None =>
          }
        case None =>
      }
      result
    }

    private def performTaint(apkDigest: String, eps: ISet[Signature], depth: Int): Unit = {
      map.get(apkDigest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              try {
                val client = new NativeDroidClient("localhost", 50051, apkDigest, reporter)
                val handler = new NativeMethodHandler(client)
                val provider: SummaryProvider = summaries.getOrElseUpdate(apkDigest, new AndroidSummaryProvider(apk))
                val jntaint = new JNTaintAnalysis(yard, apk, handler, provider, reporter, depth)
                jntaint.process(eps)
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
      performTaint(request.apkDigest)
      Future.successful(TaintAnalysisResponse(true))
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
            performTaint(request.apkDigest, Set(sig), request.depth - 1)
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
          Future.successful(GetSummaryResponse(heapSummary = heapSummary, taintResult = taintResult.getOrElse("")))
        case None => Future.failed(new RuntimeException(s"Could not load SummaryManager for apk digest: ${request.apkDigest}"))
      }
    }
  }


  def main(args: Array[String]): Unit = {
    val reporter = new PrintReporter(MsgLevel.INFO)
    if (args.length != 1) {
      reporter.error(TITLE, "Usage: apk_path")
      System.exit(0)
    }
    val apk_path = args(0)
    val dir_uri = FileUtil.toUri(apk_path)
    val ssd = JNSafGrpc.bindService(new JNSafService(dir_uri, reporter), ExecutionContext.global)
    runServer(ssd)
  }
}
