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

import io.grpc.{ServerBuilder, ServerServiceDefinition}

trait GrpcServer {
  def TITLE: String

  /**
    * Just for demo purposes
    */
  def runServer(ssd: ServerServiceDefinition, port: Int): Unit = {
    val server = ServerBuilder
      .forPort(port)
      .addService(ssd)
      .build
      .start
    println(s"$TITLE server started.")
    // make sure our server is stopped when jvm is shut down
    Runtime.getRuntime.addShutdownHook(new Thread() {
      override def run(): Unit = server.shutdown()
    })

    server.awaitTermination()
  }

}
