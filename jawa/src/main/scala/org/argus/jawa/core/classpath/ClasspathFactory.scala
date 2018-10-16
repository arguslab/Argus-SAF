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

/**
 * A trait that contains factory methods for classpath elements of type T.
 *
 * The logic has been abstracted from Classpath#ClasspathContext so it's possible
 * to have common trait that supports both recursive and flat classpath representations.
 *
 * Therefore, we expect that T will be either Classpath[U] or FlatClasspath.
 */
trait ClasspathFactory[T] {

  /**
   * Create a new classpath based on the abstract file.
   */
  def newClasspath(file: AbstractFile): T

  /**
   * Creators for sub classpaths which preserve this context.
   */
  def sourcesInPath(path: String): List[T]

  def expandPath(path: String, expandStar: Boolean = true): List[String] = Classpath.expandPath(path, expandStar)

  def expandDir(extdir: String): List[String] = Classpath.expandDir(extdir)

  def contentsOfDirsInPath(path: String): List[T] =
    for {
      dir <- expandPath(path, expandStar = false)
      name <- expandDir(dir)
      entry <- Option(AbstractFile.getDirectory(name))
    } yield newClasspath(entry)

  def classesInExpandedPath(path: String): IndexedSeq[T] =
    classesInPathImpl(path, expand = true).toIndexedSeq

  def classesInPath(path: String): List[T] = classesInPathImpl(path, expand = false)

  def classesInManifest(useManifestClasspath: Boolean): List[T] =
    if (useManifestClasspath) Classpath.manifests.map(url => newClasspath(AbstractFile getResources url))
    else Nil

  // Internal
  protected def classesInPathImpl(path: String, expand: Boolean): List[T] =
    for {
      file <- expandPath(path, expand)
      dir <- Option(AbstractFile.getDirectory(file))
    } yield newClasspath(dir)
}
