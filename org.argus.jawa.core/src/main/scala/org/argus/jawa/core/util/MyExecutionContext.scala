/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import java.util.concurrent.Executors

import scala.concurrent._

class MyExecutionContext extends ExecutionContext {
  val threadPool = Executors.newFixedThreadPool(100)

  def execute(runnable: Runnable) {
      threadPool.submit(runnable)
  }

  def reportFailure(t: Throwable) {}
}
