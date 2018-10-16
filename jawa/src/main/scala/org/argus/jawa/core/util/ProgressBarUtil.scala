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

import hu.ssh.progressbar.ProgressBar

import scala.collection.immutable.Iterable

/**
  * Created by fgwei on 5/3/17.
  */
object ProgressBarUtil {
  def withProgressBar[T, R](msg: String, pb: ProgressBar)(tasks: Iterable[T], f: T => R): Iterable[R] = {
    println(msg + " Total: " + tasks.size)
    if(tasks.isEmpty) return isetEmpty
    val progressBar = pb.withTotalSteps(tasks.size)
    progressBar.start()
    val result = tasks.map { task =>
      progressBar.tickOne()
      f(task)
    }
    progressBar.complete()
    result
  }
}
