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

import java.io.File
import java.io.FileFilter
import java.net.URL
import FileUtils._
import org.argus.jawa.core.io._

/**
 * A trait allowing to look for classpath entries of given type in directories.
 * It provides common logic for classes handling class and source files.
 * It makes use of the fact that in the case of nested directories it's easy to find a file
 * when we have a name of a package.
 */
trait DirectoryFileLookup[FileEntryType <: ClassRepClasspathEntry] extends FlatClasspath {
  val dir: File
  assert(dir != null, "Directory file in DirectoryFileLookup cannot be null")

  override def asURLs: Seq[URL] = Seq(dir.toURI.toURL)
  override def asClasspathStrings: Seq[String] = Seq(dir.getPath)

  import FlatClasspath.RootPackage
  private def getDirectory(forPackage: String): Option[File] = {
    if (forPackage == RootPackage) {
      Some(dir)
    } else {
      val packageDirName = FileUtils.dirPath(forPackage)
      val packageDir = new File(dir, packageDirName)
      if (packageDir.exists && packageDir.isDirectory) {
        Some(packageDir)
      } else None
    }
  }

  override private[jawa] def packages(inPackage: String): Seq[PackageEntry] = {
    val dirForPackage = getDirectory(inPackage)
    val nestedDirs: Array[File] = dirForPackage match {
      case None => Array.empty
      case Some(directory) => directory.listFiles(DirectoryFileLookup.packageDirectoryFileFilter)
    }
    val prefix = PackageNameUtils.packagePrefix(inPackage)
    val entries = nestedDirs map { file =>
      PackageEntryImpl(prefix + file.getName)
    }
    entries
  }

  protected def files(inPackage: String): Seq[FileEntryType] = {
    val dirForPackage = getDirectory(inPackage)
    val files: Array[File] = dirForPackage match {
      case None => Array.empty
      case Some(directory) => directory.listFiles(fileFilter)
    }
    val entries = files map { file =>
//      val wrappedFile = new scala.reflect.io.File(file)
      createFileEntry(new PlainFile(file))
    }
    entries
  }

  override private[jawa] def list(inPackage: String): FlatClasspathEntries = {
    val dirForPackage = getDirectory(inPackage)
    val files: Array[File] = dirForPackage match {
      case None => Array.empty
      case Some(directory) => directory.listFiles()
    }
    val packagePrefix = PackageNameUtils.packagePrefix(inPackage)
    val packageBuf = collection.mutable.ArrayBuffer.empty[PackageEntry]
    val fileBuf = collection.mutable.ArrayBuffer.empty[FileEntryType]
    for (file <- files) {
      if (file.isPackage) {
        val pkgEntry = PackageEntryImpl(packagePrefix + file.getName)
        packageBuf += pkgEntry
      } else if (fileFilter.accept(file)) {
//        val wrappedFile = new scala.reflect.io.File(file)
        val abstractFile = new PlainFile(file)
        fileBuf += createFileEntry(abstractFile)
      }
    }
    FlatClasspathEntries(packageBuf, fileBuf)
  }

  protected def createFileEntry(file: AbstractFile): FileEntryType
  protected def fileFilter: FileFilter
}

object DirectoryFileLookup {

  private[classpath] object packageDirectoryFileFilter extends FileFilter {
    override def accept(pathname: File): Boolean = pathname.isPackage
  }
}

case class DirectoryFlatClasspath(dir: File)
  extends DirectoryFileLookup[ClassFileEntryImpl]
  with NoSourcePaths {

  override def findClass(className: String): Option[ClassRepresentation] = findClassFile(className) map ClassFileEntryImpl

  override def findClassFile(className: String): Option[AbstractFile] = {
    val relativePath = FileUtils.dirPath(className)
    val classFile = new File(s"$dir/$relativePath.class")
    if (classFile.exists) {
//      val wrappedClassFile = new File(classFile)
      val abstractClassFile = new PlainFile(classFile)
      Some(abstractClassFile)
    } else None
  }

  override protected def createFileEntry(file: AbstractFile): ClassFileEntryImpl = ClassFileEntryImpl(file)
  override protected def fileFilter: FileFilter = DirectoryFlatClasspath.classFileFilter

  override private[jawa] def classes(inPackage: String): Seq[ClassFileEntry] = files(inPackage)
}

object DirectoryFlatClasspath {

  private val classFileFilter = new FileFilter {
    override def accept(pathname: File): Boolean = pathname.isClass
  }
}

case class DirectoryFlatSourcePath(dir: File)
  extends DirectoryFileLookup[SourceFileEntryImpl]
  with NoClasspaths {

  override def asSourcePathString: String = asClasspathString

  override protected def createFileEntry(file: AbstractFile): SourceFileEntryImpl = SourceFileEntryImpl(file)
  override protected def fileFilter: FileFilter = DirectoryFlatSourcePath.sourceFileFilter

  override def findClass(className: String): Option[ClassRepresentation] = {
    findSourceFile(className) map SourceFileEntryImpl
  }

  private def findSourceFile(className: String): Option[AbstractFile] = {
    val relativePath = FileUtils.dirPath(className)
    val sourceFile = Stream("scala", "java")
      .map(ext => new File(s"$dir/$relativePath.$ext"))
      .collectFirst { case file if file.exists() => file }

    sourceFile.map { file =>
//      val wrappedSourceFile = new scala.reflect.io.File(file)
      val abstractSourceFile = new PlainFile(file)
      abstractSourceFile
    }
  }

  override private[jawa] def sources(inPackage: String): Seq[SourceFileEntry] = files(inPackage)
}

object DirectoryFlatSourcePath {

  private val sourceFileFilter = new FileFilter {
    override def accept(pathname: File): Boolean = endsJawaOrJava(pathname.getName)
  }
}
