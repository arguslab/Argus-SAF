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

import com.google.common.hash.Hashing
import io.grpc.stub.StreamObserver
import org.argus.jawa.core.io.{MsgLevel, PrintReporter, Reporter}
import org.argus.jawa.core.util.{FileResourceUri, FileUtil}
import org.argus.jnsaf.server.jnsaf_grpc.{JNSafGrpc, LoadAPKRequest, LoadAPKResponse}

import scala.concurrent.ExecutionContext

object JNSafServer extends GrpcServer {
  def TITLE = "JNSafService"

  class JNSafService(apk_uri: FileResourceUri, reporter: Reporter) extends JNSafGrpc.JNSaf {
    val dir: File = FileUtil.toFile(apk_uri)
    if (!dir.exists()) {
      dir.mkdirs()
    }
    def loadAPK(responseObserver: StreamObserver[LoadAPKResponse]): StreamObserver[LoadAPKRequest] = {
      val byteStream = new ByteArrayOutputStream
      val sha256 = Hashing.sha256()
      new StreamObserver[LoadAPKRequest] {
        def onNext(request: LoadAPKRequest): Unit = {
          val data = request.buffer.toByteArray
          byteStream.write(data)
          sha256.hashBytes(data)
        }

        def onError(t: Throwable): Unit = {
          reporter.echo(TITLE,"Client LoadBinaryResponse onError")
          responseObserver.onError(t)
        }

        def onCompleted(): Unit = {
          val apk_digest = sha256.toString
          byteStream.writeTo(new BufferedOutputStream(new FileOutputStream(new File(dir, apk_digest))))
          responseObserver.onNext(LoadAPKResponse(apkDigest = apk_digest, length = byteStream.size()))
          responseObserver.onCompleted()
        }
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
    val apk_uri = FileUtil.toUri(apk_path)
    val ssd = JNSafGrpc.bindService(new JNSafService(apk_uri, reporter), ExecutionContext.global)
    runServer(ssd)
  }
}
