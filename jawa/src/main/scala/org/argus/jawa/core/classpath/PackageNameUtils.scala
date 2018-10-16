/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.classpath

import org.argus.jawa.core.classpath.FlatClasspath.RootPackage

/**
 * Common methods related to package names represented as String
 */
object PackageNameUtils {

  /**
   * @param fullClassName full class name with package
   * @return (package, simple class name)
   */
  def separatePkgAndClassNames(fullClassName: String): (String, String) = {
    val lastDotIndex = fullClassName.lastIndexOf('.')
    if (lastDotIndex == -1)
      (RootPackage, fullClassName)
    else
      (fullClassName.substring(0, lastDotIndex), fullClassName.substring(lastDotIndex + 1))
  }

  def packagePrefix(inPackage: String): String = if (inPackage == RootPackage) "" else inPackage + "."
}
