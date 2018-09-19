/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta

import org.argus.jawa.core.{JawaClass, ScopeManager}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object PTAScopeManager extends ScopeManager{
  private var passSystemLibrary = true
  private var passUserLibrary = true
  private var passApplication = false
  def setMode(passSystemLibrary: Boolean, passUserLibrary: Boolean, passApplication: Boolean): Unit = {
    this.passSystemLibrary = passSystemLibrary
    this.passUserLibrary = passUserLibrary
    this.passApplication = passApplication
  }
  
  /**
   * return true if given record needs to be bypassed
   */
  def shouldBypass(rec: JawaClass): Boolean = {
    if(this.passSystemLibrary && rec.isSystemLibraryClass) true
    else if(this.passUserLibrary && rec.isUserLibraryClass) true
    else if(this.passApplication && rec.isApplicationClass) true
    else false
  }
}
