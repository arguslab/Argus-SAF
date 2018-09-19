/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import org.argus.jawa.core.io.Reporter

object TimeUtil {
  def timed[T](label: String, reporter: Reporter)(t: => T): T = {
    val start = System.nanoTime
    val result = t
    val elapsed = System.nanoTime - start
    reporter.echo(label, (elapsed/1e9) + " s")
    result
  }
}
