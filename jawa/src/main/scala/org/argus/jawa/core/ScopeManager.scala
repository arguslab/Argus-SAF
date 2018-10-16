/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait ScopeManager {
  /**
   * return true if given record needs to be bypassed
   */
  def shouldBypass(rec: JawaClass): Boolean
}

class DefaultScopeManager extends ScopeManager {
  def shouldBypass(rec: JawaClass): Boolean = false
}

object ScopeManager{
  private var currentScopeManager: ScopeManager = new DefaultScopeManager
  def setScopeManager(manager: ScopeManager): Unit = this.synchronized(this.currentScopeManager = manager)
  def getCurrentScopeManager: ScopeManager = this.currentScopeManager
}
