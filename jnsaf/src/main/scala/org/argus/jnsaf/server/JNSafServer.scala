/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
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
import org.argus.jawa.flow.summary.{SummaryManager, SummaryProvider, SummaryToProto}
import org.argus.jawa.flow.summary.susaf.rule.HeapSummary
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

    def taintAnalysis(request: TaintAnalysisRequest): Future[TaintAnalysisResponse] = {
      val digest = request.apkDigest
      var status = false
      map.get(digest) match {
        case Some(uri) =>
          yard.getApk(uri) match {
            case Some(apk) =>
              TimeUtil.timed("TaintAnalysis Running Time", reporter) {
                try {
                  val client = new NativeDroidClient("localhost", 50051, reporter)
                  val handler = new NativeMethodHandler(client)
                  val provider: SummaryProvider = summaries.getOrElseUpdate(digest, new AndroidSummaryProvider(apk))
                  val jntaint = new JNTaintAnalysis(apk, handler, provider, reporter)
                  jntaint.process
                } catch {
                  case e: Throwable =>
                    e.printStackTrace()
                }
              }
              status = true
            case None =>
          }
        case None =>
      }
      Future.successful(TaintAnalysisResponse(status))
    }

    def getSummary(request: GetSummaryRequest): Future[GetSummaryResponse] = {
     summaries.get(request.apkDigest) match {
       case Some(provider) =>
         val sig = Signature(request.getMethodSignature)
         provider.getSummaryManager.getSummary[HeapSummary](sig) match {
           case Some(s) => Future.successful(GetSummaryResponse(heapSummary = Some(SummaryToProto.toProto(s))))
           case None =>
             if (request.gen && request.depth > 0) {
               // TODO: not handled yet.
               Future.successful(GetSummaryResponse())
             } else {
               Future.successful(GetSummaryResponse())
             }
         }
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
