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
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util._
import org.argus.nativedroid.server.nativedroid_grpc._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

/**
  * gRPC client to communicate with NativeDroid Server.
  */
//noinspection ScalaDeprecation
class NativeDroidClient(address: String, port: Int, apkDigest: String, reporter: Reporter) {
  final val TITLE = "NativeDroidClient"
  private val channel = ManagedChannelBuilder.forAddress(address, port).usePlaintext(true).build
  private val client = NativeDroidGrpc.stub(channel)
  private val blocking_client = NativeDroidGrpc.blockingStub(channel)
  private val loadedBinaries: MMap[FileResourceUri, String] = mmapEmpty

  @throws[InterruptedException]
  def shutdown(): Unit = {
    channel.shutdown.awaitTermination(5, TimeUnit.SECONDS)
  }

  private def startStream(fileUri: FileResourceUri): Option[String] = {
    val doneSignal = new CountDownLatch(1)
    val responseObserver = new StreamObserver[LoadBinaryResponse]() {
      override def onNext(value: LoadBinaryResponse): Unit = {
        loadedBinaries(fileUri) = value.soDigest
        reporter.echo(TITLE,s"Client loaded binary: $fileUri")
      }

      override def onError(t: Throwable): Unit = {
        reporter.echo(TITLE,"Client LoadBinaryResponse onError")
        doneSignal.countDown()
      }

      override def onCompleted(): Unit = {
        reporter.echo(TITLE,"Client LoadBinaryResponse onCompleted")
        doneSignal.countDown()
      }
    }
    val requestObserver = client.loadBinary(responseObserver)
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
          val byteString = ByteString.copyFrom(buffer)
          val req = LoadBinaryRequest(byteString)
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
    loadedBinaries.get(fileUri)
  }

  def loadBinary(soFileUri: FileResourceUri): Option[String] = {
    reporter.echo(TITLE,"Client loadBinary")
    try {
      startStream(soFileUri)
    } catch {
      case e: Exception =>
        e.printStackTrace()
        None
    }
  }

  private def getBinaryDigest(soFileUri: FileResourceUri): String = {
    this.loadedBinaries.get(soFileUri) match {
      case Some(soDigest) => soDigest
      case None =>
        loadBinary(soFileUri) match {
          case Some(soDigest) => soDigest
          case None =>
            throw new RuntimeException(s"Load binary $soFileUri failed.")
        }
    }
  }

  def hasSymbol(soFileUri: FileResourceUri, symbol: String): Boolean = {
    reporter.echo(TITLE,s"Client hasSymbol: $symbol")
    try {
      val soDigest = getBinaryDigest(soFileUri)
      val response = blocking_client.hasSymbol(HasSymbolRequest(soDigest, symbol))
      response.hasSymbol
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        e.printStackTrace()
        false
    }
  }

  def hasNativeActivity(soFileUri: FileResourceUri, customEntry: Option[String]): Boolean = {
    reporter.echo(TITLE,"Client hasNativeActivity")
    customEntry match {
      case Some(entry) => hasSymbol(soFileUri, entry)
      case None =>
        if(hasSymbol(soFileUri, "android_main")) {
          true
        } else {
          hasSymbol(soFileUri, "ANativeActivity_onCreate")
        }
    }
  }

  def getSoFileUri(dirUri: FileResourceUri, soFileName: String, order: IList[String] = List("armeabi", "armeabi-v7a", "x86", "mips")): Option[FileResourceUri] = {
    val soFiles: IMap[String, FileResourceUri] = FileUtil.listFiles(dirUri, soFileName, recursive = true).map { soUri =>
      val f = FileUtil.toFile(soUri)
      (f.getParentFile.getName, soUri)
    }.toMap
    val archOpt: Option[String] = order.find { arch =>
      soFiles.contains(arch)
    }
    archOpt.map { arch =>
      soFiles.getOrElse(arch, throw new RuntimeException("Should never be here."))
    }
  }

  def getAllSoFilePath(dirUri: FileResourceUri, order: IList[String] = List("armeabi", "armeabi-v7a", "x86", "mips")): IList[FileResourceUri] = {
    val soFiles = FileUtil.listFiles(dirUri, ".so", recursive = true)
    val res: MList[FileResourceUri] = mlistEmpty
    order.foreach { arch =>
      soFiles.foreach { soUri =>
        val f = FileUtil.toFile(soUri)
        if(f.getParentFile.getName == arch) {
          res += soUri
        }
      }
    }
    res.toList
  }

  def genSummary(soFileUri: FileResourceUri, componentName: String, methodName: String, sig: Signature, depth: Int): (String, String) = {
    reporter.echo(TITLE,s"Client genSummary for $sig")
    if(hasSymbol(soFileUri, methodName)) {
      try {
        val doneSignal = new CountDownLatch(1)
        val soDigest = getBinaryDigest(soFileUri)
        val request = GenSummaryRequest(apkDigest, componentName, depth, soDigest, methodName, Some(sig.method_signature))
        val responseFuture: Future[GenSummaryResponse] = client.genSummary(request)
        var responseOpt: Option[GenSummaryResponse] = None
        responseFuture.foreach { response =>
          responseOpt = Some(response)
          doneSignal.countDown()
        }
        if (!doneSignal.await(5, TimeUnit.MINUTES)) {
          reporter.error(TITLE, "genSummary can not finish within 5 minutes")
        }
        responseOpt match {
          case Some(response) =>
            reporter.echo(TITLE, s"Analyzed ${response.analyzedInstructions} instructions")
            return (response.taint, response.summary.trim)
          case None =>
        }
      } catch {
        case e: Throwable =>
          reporter.error(TITLE, e.getMessage)
          e.printStackTrace()
      }
    }
    ("", s"`${sig.signature}`:;")
  }

  def analyseNativeActivity(soFileUri: FileResourceUri, customEntry: Option[String]): String = {

    try {
      //      val mainModule = PyModule.importModule("nativedroid")
      //      var obj: PyObject = null
      //      TimeUtil.timed("NativeDroid native_activity_analysis", reporter) {
      //        obj = mainModule.call("native_activity_analysis", soFile, customEntry.getOrElse(""), native_ss_file, java_ss_file)
      //      }
      //      val v = obj.getStringValue
      //      reporter.echo("Analyzed instructions", v)
      //      v
      "1"
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        e.printStackTrace()
        "-1"
    }
  }
}