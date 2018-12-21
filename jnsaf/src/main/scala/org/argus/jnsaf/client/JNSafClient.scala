/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.client

import java.io.{BufferedInputStream, FileInputStream, FileNotFoundException, IOException}
import java.util.concurrent.{CountDownLatch, TimeUnit}

import com.google.protobuf.ByteString
import io.grpc.ManagedChannelBuilder
import io.grpc.stub.StreamObserver
import org.argus.amandroid.plugin.TaintAnalysisApproach
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util._
import org.argus.jawa.flow.taint_result.TaintResult
import org.argus.jnsaf.server.jnsaf_grpc._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

//noinspection ScalaDeprecation
class JNSafClient(address: String, port: Int, reporter: Reporter) {
  final val TITLE = "JNSafClient"
  private val channel = ManagedChannelBuilder.forAddress(address, port).usePlaintext(true).build
  private val client = JNSafGrpc.stub(channel)
//  private val blocking_client = JNSafGrpc.blockingStub(channel)

  private val loadedAPKs: MMap[FileResourceUri, String] = mmapEmpty

  @throws[InterruptedException]
  def shutdown(): Unit = {
    channel.shutdown.awaitTermination(5, TimeUnit.SECONDS)
  }

  private def startStream(fileUri: FileResourceUri): Option[String] = {
    val doneSignal = new CountDownLatch(1)
    val responseObserver = new StreamObserver[LoadAPKResponse]() {
      override def onNext(value: LoadAPKResponse): Unit = {
        loadedAPKs(fileUri) = value.apkDigest
        reporter.echo(TITLE,"Client LoadAPKResponse onNext")
      }

      override def onError(t: Throwable): Unit = {
        reporter.echo(TITLE,"Client LoadAPKResponse onError")
        doneSignal.countDown()
      }

      override def onCompleted(): Unit = {
        reporter.echo(TITLE,"Client LoadAPKResponse onCompleted")
        doneSignal.countDown()
      }
    }
    val requestObserver = client.loadAPK(responseObserver)
    try {
      val file = FileUtil.toFile(fileUri)
      if (!file.exists) {
        reporter.echo(TITLE,"File does not exist")
        return None
      }
      try {
        val bInputStream = new BufferedInputStream(new FileInputStream(file))
        val bufferSize = 1024 * 1024 // 1M
        val buffer = new Array[Byte](bufferSize)
        var tmp = 0
        var size = 0
        while ( {
          tmp = bInputStream.read(buffer); tmp > 0
        }) {
          size += tmp
          val byteString = ByteString.copyFrom(buffer, 0, tmp)
          val req = LoadAPKRequest(byteString)
          requestObserver.onNext(req)
        }
      } catch {
        case e: FileNotFoundException =>
          e.printStackTrace()
        case e: IOException =>
          e.printStackTrace()
      }
    } catch {
      case e: RuntimeException =>
        requestObserver.onError(e)
        throw e
    }
    requestObserver.onCompleted()
    // Receiving happens asynchronously
    if (!doneSignal.await(1, TimeUnit.MINUTES)) {
      reporter.error(TITLE, "loadBinary can not finish within 1 minutes")
    }
    loadedAPKs.get(fileUri)
  }

  def loadAPK(apkUri: FileResourceUri): Option[String] = {
    reporter.echo(TITLE,"Client loadApk")
    try {
      startStream(apkUri)
    } catch {
      case e: Exception =>
        e.printStackTrace()
        None
    }
  }

  def taintAnalysis(apkUri: FileResourceUri, approach: TaintAnalysisApproach.Value): Option[TaintResult] = {
    reporter.echo(TITLE,"Client taintAnalysis")
    try {
      val doneSignal = new CountDownLatch(1)
      val digest = getAPKDigest(apkUri)
      val algo = approach match {
        case TaintAnalysisApproach.COMPONENT_BASED =>
          TaintAnalysisRequest.Algorithm.COMPONENT_BASED
        case TaintAnalysisApproach.BOTTOM_UP =>
          TaintAnalysisRequest.Algorithm.BOTTOM_UP
      }
      val request = TaintAnalysisRequest(digest, algo)
      val responseFuture: Future[TaintAnalysisResponse] = client.taintAnalysis(request)
      var responseOpt: Option[TaintAnalysisResponse] = None
      responseFuture.foreach { response =>
        responseOpt = Some(response)
        doneSignal.countDown()
      }
      if (!doneSignal.await(5, TimeUnit.MINUTES)) {
        reporter.error(TITLE, "genSummary can not finish within 5 minutes")
      }
      responseOpt match {
        case Some(response) =>
          return response.taintResult
        case None =>
      }
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        e.printStackTrace()
    }
    None
  }

  private def getAPKDigest(apkUri: FileResourceUri): String = {
    this.loadedAPKs.get(apkUri) match {
      case Some(soDigest) => soDigest
      case None =>
        loadAPK(apkUri) match {
          case Some(soDigest) => soDigest
          case None =>
            throw new RuntimeException(s"Load binary $apkUri failed.")
        }
    }
  }
}