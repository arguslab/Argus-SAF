/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.classpath

import org.argus.jawa.core.io.AbstractFile
import FileUtils._

/**
 * Provides factory methods for flat classpath. When creating classpath instances for a given path,
 * it uses proper type of classpath depending on a types of particular files containing sources or classes.
 */
class FlatClasspathFactory extends ClasspathFactory[FlatClasspath] {

  override def newClasspath(file: AbstractFile): FlatClasspath =
    if (file.isJarOrZip)
      ZipAndJarFlatClasspathFactory.create(file)
    else if (file.isDirectory)
      new DirectoryFlatClasspath(file.file)
    else
      sys.error(s"Unsupported classpath element: $file")

  override def sourcesInPath(path: String): List[FlatClasspath] =
    for {
      file <- expandPath(path, expandStar = false)
      dir <- Option(AbstractFile getDirectory file)
    } yield createSourcePath(dir)

  private def createSourcePath(file: AbstractFile): FlatClasspath =
    if (file.isJarOrZip)
      ZipAndJarFlatSourcepathFactory.create(file)
    else if (file.isDirectory)
      new DirectoryFlatSourcePath(file.file)
    else
      sys.error(s"Unsupported sourcepath element: $file")
}
