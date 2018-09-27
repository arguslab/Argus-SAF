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

import java.io.{File, FileInputStream}

import com.google.common.hash.Hashing
import io.grpc.{Server, ServerBuilder}
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.argus.jnsaf.client.JNSafClient
import org.argus.jnsaf.server.JNSafServer.{JNSafService, TITLE}
import org.argus.jnsaf.server.jnsaf_grpc.JNSafGrpc
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}

import scala.concurrent.ExecutionContext

class JNSafServerTest extends FlatSpec with Matchers with BeforeAndAfterAll {
  var server: Server = _
  var client: JNSafClient = _
  override def beforeAll(): Unit = {
    val reporter = new PrintReporter(MsgLevel.INFO)
    val apk_path = "/tmp/apks"
    val apk_uri = FileUtil.toUri(apk_path)
    val ssd = JNSafGrpc.bindService(new JNSafService(apk_uri, reporter), ExecutionContext.global)
    server = ServerBuilder
      .forPort(55001)
      .addService(ssd)
      .build
      .start
    println(s"$TITLE server started.")
    client = new JNSafClient("localhost", 55001, reporter)
  }

  override def afterAll(): Unit = {
    if(server != null) {
      server.shutdown()
      server = null
    }
    if(client != null) {
      client.shutdown()
      client = null
    }
    println(s"$TITLE server stopped.")
    val dir = new File("/tmp/apks")
    dir.delete()
  }

  "loadApk" should "success" in {
    val file_path = getClass.getResource("/NativeFlowBench/native_leak.apk").getPath
    val file_uri = FileUtil.toUri(file_path)
    val res = client.loadAPK(file_uri)
    assert(res.isDefined)
    val file = FileUtil.toFile(file_uri)
    val sha256 = Hashing.sha256()
    sha256.hashBytes(new FileInputStream(file).readAllBytes())
    assert(sha256.toString == res.get)
  }

}
