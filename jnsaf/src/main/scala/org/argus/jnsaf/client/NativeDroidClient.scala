/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.client

import io.grpc.{ManagedChannel, ManagedChannelBuilder}
import io.grpc.stub.StreamObserver
import org.argus.nativedroid.server.server.{LoadBinaryRequest, LoadBinaryResponse, NativeDroidServerGrpc}

import scala.concurrent.{Await, Promise}

/**
  * gRPC client to communicate with NativeDroid Server.
  */
class NativeDroidClient {
  val channel = ManagedChannelBuilder.forAddress("localhost", 50051).usePlaintext().build
  val client = NativeDroidServerGrpc.stub(channel)

  def loadBinary(soFile: String): Boolean = {
    def observer(p: Promise[String]): StreamObserver[LoadBinaryResponse] =
      new StreamObserver[LoadBinaryResponse] {
        def onError(t: Throwable): Unit = {
          println(s"ON_ERROR: $t")
          p.complete(tryAwaitTermination(channel, "received onError"))
        }
        def onCompleted(): Unit = {
          println("ON_COMPLETED")
          p.complete(tryAwaitTermination(channel, "received onComplete"))
        }
        def onNext(response: TimeResponse): Unit =
          println(s"ON_NEXT: Received current time ms: ${response.currentTime}")
      }
    val terminated = Promise[String]
    client.loadBinary(LoadBinaryRequest(), observer(terminated))

    val shutdownReason = Await.result(terminated.future, Duration.Inf)
    println(s"Successfully shutdown application. Reason: $shutdownReason")
  }




}
