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

import scala.concurrent.Await
import scala.concurrent.duration.Duration
import scala.util._

object TaskRunner {
  private final val TITLE = "TaskRunner"
  def execute[T](task: Task[T], timeoutOpt: Option[Int] = None): Unit = {
    import scala.concurrent.ExecutionContext.Implicits.global
    val (f, cancel) = FutureUtil.interruptableFuture[T] { () =>
      task.run
    }
    f.onComplete {
      case Success(sth) =>
        println(TITLE, sth.toString)
      case Failure(ex) =>
        System.err.println(TITLE, ex.getMessage)
    }
    try{
      val d = timeoutOpt match {
        case Some(t) => Duration(t, "s")
        case None => Duration("Inf")
      }
      Await.result(f, d)
    } catch {
      case te: Throwable =>
        cancel()
    }
    
  }
}

trait Task[T] {
  def run: T
}
