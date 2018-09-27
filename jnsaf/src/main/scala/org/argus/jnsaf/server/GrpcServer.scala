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

import io.grpc.{ServerBuilder, ServerServiceDefinition}

trait GrpcServer {
  def TITLE: String

  /**
    * Just for demo purposes
    */
  def runServer(ssd: ServerServiceDefinition): Unit = {
    val server = ServerBuilder
      .forPort(55001)
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
