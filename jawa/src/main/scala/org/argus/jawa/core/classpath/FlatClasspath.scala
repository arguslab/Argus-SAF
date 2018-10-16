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
 * A base trait for the particular flat classpath representation implementations.
 *
 * We call this variant of a classpath representation flat because it's possible to
 * query the whole classpath using just single instance extending this trait.
 *
 */
trait FlatClasspath extends ClassFileLookup {
  /** Empty string represents root package */
  private[jawa] def packages(inPackage: String): Seq[PackageEntry]
  private[jawa] def classes(inPackage: String): Seq[ClassFileEntry]
  private[jawa] def sources(inPackage: String): Seq[SourceFileEntry]

  /** Allows to get entries for packages and classes merged with sources possibly in one pass. */
  private[jawa] def list(inPackage: String): FlatClasspathEntries

  // A default implementation which should be overridden, if we can create more efficient
  // solution for given type of FlatClasspath
  override def findClass(className: String): Option[ClassRepresentation] = {
    val (pkg, simpleClassName) = PackageNameUtils.separatePkgAndClassNames(className)

    val foundClassFromClassFiles = classes(pkg)
      .find(_.name == simpleClassName)

    def findClassInSources = sources(pkg)
      .find(_.name == simpleClassName)

    foundClassFromClassFiles orElse findClassInSources
  }

  override def asClasspathString: String = Classpath.join(asClasspathStrings: _*)
  def asClasspathStrings: Seq[String]
}

object FlatClasspath {
  val RootPackage = ""
}

case class FlatClasspathEntries(packages: Seq[PackageEntry], classesAndSources: Seq[ClassRepClasspathEntry])

object FlatClasspathEntries {
  import scala.language.implicitConversions

  // to have working unzip method
  implicit def entry2Tuple(entry: FlatClasspathEntries): (Seq[PackageEntry], Seq[ClassRepClasspathEntry]) = (entry.packages, entry.classesAndSources)
}

sealed trait ClassRepClasspathEntry extends ClassRepresentation

trait ClassFileEntry extends ClassRepClasspathEntry {
  def file: AbstractFile
}

trait SourceFileEntry extends ClassRepClasspathEntry {
  def file: AbstractFile
}

trait PackageEntry {
  def name: String
}

private[jawa] case class ClassFileEntryImpl(file: AbstractFile) extends ClassFileEntry {
  override def name: String = FileUtils.stripClassExtension(file.name) // class name

  override def binary: Option[AbstractFile] = Some(file)
  override def source: Option[AbstractFile] = None
}

private[jawa] case class SourceFileEntryImpl(file: AbstractFile) extends SourceFileEntry {
  override def name: String = FileUtils.stripSourceExtension(file.name)

  override def binary: Option[AbstractFile] = None
  override def source: Option[AbstractFile] = Some(file)
}

private[jawa] case class ClassAndSourceFilesEntry(classFile: AbstractFile, srcFile: AbstractFile) extends ClassRepClasspathEntry {
  override def name: String = FileUtils.stripClassExtension(classFile.name)

  override def binary: Option[AbstractFile] = Some(classFile)
  override def source: Option[AbstractFile] = Some(srcFile)
}

private[jawa] case class PackageEntryImpl(name: String) extends PackageEntry

private[jawa] trait NoSourcePaths {
  def asSourcePathString: String = ""
  private[jawa] def sources(inPackage: String): Seq[SourceFileEntry] = Seq.empty
}

private[jawa] trait NoClasspaths {
  def findClassFile(className: String): Option[AbstractFile] = None
  private[jawa] def classes(inPackage: String): Seq[ClassFileEntry] = Seq.empty
}
