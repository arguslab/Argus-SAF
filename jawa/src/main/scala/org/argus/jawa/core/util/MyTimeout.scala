/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import scala.concurrent.duration.FiniteDuration
import java.util.concurrent.TimeoutException

class MyTimeout(time: FiniteDuration) {
  private final var startTime: Long = System.currentTimeMillis()
  def refresh(): Unit = this.startTime = System.currentTimeMillis()
  def isTimeout: Boolean = {
    val currentTime = System.currentTimeMillis()
    (currentTime - startTime) >= time.toMillis
  }
  def timeoutThrow(): Unit = {
    if(isTimeout) throw new TimeoutException("Timeout after " + time.toMinutes + " minutes.")
  }
}
