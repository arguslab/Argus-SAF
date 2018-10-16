/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.secret

/**
  * Created by fgwei on 3/16/17.
  */
class Data {
  private var d: String = _
  def set(d: String): Unit = this.d = d
  def get(): String = this.d
}
