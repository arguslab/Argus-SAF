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

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait Adapter[U, T] {
  def adapt(u : U) : T
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
object Adapter {
  def usingF[U, T, R](u : U)(f : T => R)(implicit a : Adapter[U, T]) : R =
    f(a.adapt(u))

  def using[U, T](u : U)(f : T => Unit)(implicit a : Adapter[U, T]) : Unit =
    f(a.adapt(u))

  def foreach[U, T](u : U)(f : T => Unit)(implicit a : Adapter[U, T]) {
    f(a.adapt(u))
  }
}