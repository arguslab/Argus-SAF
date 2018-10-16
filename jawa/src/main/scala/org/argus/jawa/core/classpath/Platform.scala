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

import org.argus.jawa.core.io.AbstractFile

/** The platform dependent pieces of Global.
 */
trait Platform {

  /** The old, recursive implementation of compiler classpath. */
  def classPath: Classpath

  /** The new implementation of compiler classpath. */
  private[jawa] def flatClassPath: FlatClasspath

  /** Update classpath with a substitution that maps entries to entries */
  def updateClassPath(subst: Map[Classpath, Classpath])

  /**
   * Tells whether a class with both a binary and a source representation
   * (found in classpath and in sourcepath) should be re-compiled. Behaves
   * on the JVM similar to javac, i.e. if the source file is newer than the classfile,
   * a re-compile is triggered. On .NET by contrast classfiles always take precedence.
   */
  def needCompile(bin: AbstractFile, src: AbstractFile): Boolean
}
