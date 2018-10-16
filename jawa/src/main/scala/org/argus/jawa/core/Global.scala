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

import org.argus.jawa.core.io.Reporter

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class Global(val projectName: String, val reporter: Reporter) extends JawaClassLoadManager
  with JawaClasspathManager {
  
  /**
   * reset the current Global
   */
  def reset(removeCode: Boolean = true): Unit = {
    this.hierarchy.reset()
    if(removeCode) {
      this.applicationClassCodes.clear()
      this.userLibraryClassCodes.clear()
    }
    this.cachedClassRepresentation.invalidateAll()
    this.classCache.invalidateAll()
    this.methodCache.invalidateAll()
  }
}
