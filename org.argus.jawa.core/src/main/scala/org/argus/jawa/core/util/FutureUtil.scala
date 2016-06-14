/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import java.util.concurrent.atomic.AtomicReference

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent._
import scala.util.Failure

object FutureUtil {
  
  def cancellableFuture[T](fun: Future[T] => T)(implicit ex: ExecutionContext): (Future[T], () => Boolean) = {
    val p = Promise[T]()
    val f = p.future
    val funFuture = Future(fun(f))
    p tryCompleteWith funFuture                              // Scala 2.10
    
    (f, () => p.tryFailure(new CancellationException))       // Scala 2.10
  }
  
  def interruptableFuture[T](fun: () => T)(implicit ex: ExecutionContext): (Future[T], () => Boolean) = {
    val p = Promise[T]()
    val f = p.future
    val aref = new AtomicReference[Thread](null)
    val funFuture = Future {
      val thread = Thread.currentThread
      aref.synchronized { aref.set(thread) }
      try fun() finally {
//        val wasInterrupted = aref.synchronized {
//          aref getAndSet null
//        } ne thread
        // Deal with interrupted flag of this thread in desired
      }
    }
    funFuture.onComplete(p tryComplete)                    // Akka 2.0
//    p tryCompleteWith funFuture                             // Scala 2.10
 
    (f, () => {
      aref.synchronized { Option(aref getAndSet null) foreach { _.interrupt() } }
      p.tryComplete(Failure(new CancellationException))          // Akka 2.0
//      p.tryFailure(new CancellationException("Future canceled!"))               // Scala 2.10
    })
  }
}
