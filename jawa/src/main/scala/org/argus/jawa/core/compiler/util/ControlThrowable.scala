/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.util

/** A marker trait indicating that the `Throwable` it is mixed into is
 *  intended for flow control.
 *
 *  Note that `Throwable` subclasses which extend this trait may extend any
 *  other `Throwable` subclass (eg. `RuntimeException`) and are not required
 *  to extend `Throwable` directly.
 *
 *  Instances of `Throwable` subclasses marked in this way should not normally
 *  be caught. Where catch-all behaviour is required `ControlThrowable`
 *  should be propagated, for example:
 *  {{{
 *  import scala.util.control.ControlThrowable
 *
 *  try {
 *    // Body might throw arbitrarily
 *  } catch {
 *    case c: ControlThrowable => throw c // propagate
 *    case t: Exception        => log(t)  // log and suppress
 *  }
 *  }}}
 *
 *  @author Miles Sabin
 */
trait ControlThrowable extends Throwable
