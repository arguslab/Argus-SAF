/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.classpath

import org.argus.jawa.core.io.AbstractFile
import org.argus.jawa.core.{ClasspathRepresentationType, Global}

trait JavaPlatform extends Platform {
  val global: Global
  val javaLib: String
  import global._

  private[jawa] var currentClassPath: Option[MergedClasspath] = None

  def classPath: Classpath = {
    assert(classpathImpl == ClasspathRepresentationType.Recursive,
      "To use recursive classpath representation you must enable it with recursive compiler option.")

    if (currentClassPath.isEmpty) currentClassPath = Some(new PathResolver(javaLib).result)
    currentClassPath.get
  }

  private[jawa] lazy val flatClassPath: FlatClasspath = {
    assert(classpathImpl == ClasspathRepresentationType.Flat,
      "To use flat classpath representation you must enable it with flat compiler option.")

    new FlatClasspathResolver(javaLib).result
  }

  /** Update classpath with a substituted subentry */
  def updateClassPath(subst: Map[Classpath, Classpath]): Unit =
    currentClassPath = Some(new DeltaClasspath(currentClassPath.get, subst))


  def needCompile(bin: AbstractFile, src: AbstractFile): Boolean =
    src.lastModified >= bin.lastModified
}
