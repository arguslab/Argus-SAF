/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.util

/** A trait for exceptions which, for efficiency reasons, do not
 *  fill in the stack trace.  Stack trace suppression can be disabled
 *  on a global basis via a system property wrapper in
 *  [[scala.sys.SystemProperties]].
 *
 *  @author   Paul Phillips
 *  @since    2.8
 */
trait NoStackTrace extends Throwable {
  override def fillInStackTrace(): Throwable =
    if (NoStackTrace.noSuppression) super.fillInStackTrace()
    else this
}

object NoStackTrace {
  final def noSuppression: Boolean = _noSuppression

  // two-stage init to make checkinit happy, since sys.SystemProperties.noTraceSupression.value calls back into NoStackTrace.noSuppression
  final private var _noSuppression = false
  _noSuppression = sys.SystemProperties.noTraceSuppression.value
}
