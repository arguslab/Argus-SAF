/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
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
