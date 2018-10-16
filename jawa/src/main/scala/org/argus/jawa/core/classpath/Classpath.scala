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

import org.argus.jawa.core.io.{AbstractFile, Directory, File, Jar}
import java.net.MalformedURLException
import java.net.URL
import java.util.regex.PatternSyntaxException

import scala.collection.{immutable, mutable}
import FileUtils.endsClass
import FileUtils.endsJawaOrJava

/** <p>
 *    This module provides star expansion of '-classpath' option arguments, behaves the same as
 *    java, see [http://java.sun.com/javase/6/docs/technotes/tools/windows/classpath.html]
 *  </p>
 *
 *  @author Stepan Koltsov
 */
object Classpath {
  import scala.language.postfixOps

  /** Expand single path entry */
  private def expandS(pattern: String): List[String] = {
    val wildSuffix = File.separator + "*"

    /* Get all subdirectories, jars, zips out of a directory. */
    def lsDir(dir: Directory, filt: String => Boolean = _ => true) =
      dir.list filter (x => filt(x.name) && (x.isDirectory || Jar.isJarOrZip(x))) map (_.path) toList

    if (pattern == "*") lsDir(Directory("."))
    else if (pattern endsWith wildSuffix) lsDir(Directory(pattern dropRight 2))
    else if (pattern contains '*') {
      try {
        val regexp = ("^" + pattern.replaceAllLiterally("""\*""", """.*""") + "$").r
        lsDir(Directory(pattern).parent, regexp findFirstIn _ isDefined)
      }
      catch { case _: PatternSyntaxException => List(pattern) }
    }
    else List(pattern)
  }

  /** Split classpath using platform-dependent path separator */
  def split(path: String): List[String] = (path split File.pathSeparator).toList filterNot (_ == "") distinct

  /** Join classpath using platform-dependent path separator */
  def join(paths: String*): String  = paths filterNot (_ == "") mkString File.pathSeparator

  /** Split the classpath, apply a transformation function, and reassemble it. */
  def map(cp: String, f: String => String): String = join(split(cp) map f: _*)

  /** Expand path and possibly expanding stars */
  def expandPath(path: String, expandStar: Boolean = true): List[String] =
    if (expandStar) split(path) flatMap expandS
    else split(path)

  /** Expand dir out to contents, a la extdir */
  def expandDir(extdir: String): List[String] = {
    AbstractFile getDirectory extdir match {
      case null => Nil
      case dir  => dir filter (_.isClassContainer) map (x => new java.io.File(dir.file, x.name) getPath) toList
    }
  }
  /** Expand manifest jar classpath entries: these are either urls, or paths
   *  relative to the location of the jar.
   */
  def expandManifestPath(jarPath: String): List[URL] = {
    val file = File(jarPath)
    if (!file.isFile) return Nil

    val baseDir = file.parent
    new Jar(file).classPathElements map (elem =>
      specToURL(elem) getOrElse (baseDir / elem).toURL
    )
  }

  def specToURL(spec: String): Option[URL] =
    try Some(new URL(spec))
    catch { case _: MalformedURLException => None }

  /** A class modeling aspects of a Classpath which should be
   *  propagated to any classpaths it creates.
   */
  abstract class ClasspathContext extends ClasspathFactory[Classpath] {
    /** A filter which can be used to exclude entities from the classpath
     *  based on their name.
     */
    def isValidName(name: String): Boolean = true

    /** Filters for assessing validity of various entities.
     */
    def validClassFile(name: String): Boolean = endsClass(name) && isValidName(name)
    def validPackage(name: String): Boolean = (name != "META-INF") && (name != "") && (name.charAt(0) != '.')
    def validSourceFile(name: String): Boolean = endsJawaOrJava(name)

    /** From the representation to its identifier.
     */
    def toBinaryName(rep: AbstractFile): String

    def sourcesInPath(path: String): List[Classpath] =
      for (file <- expandPath(path, expandStar = false) ; dir <- Option(AbstractFile getDirectory file)) yield
        new SourcePath(dir, this)
  }

  def manifests: List[java.net.URL] = {
    import collection.JavaConverters._
    Thread.currentThread().getContextClassLoader
      .getResources("META-INF/MANIFEST.MF")
      .asScala
      .filter(_.getProtocol == "jar").toList
  }

  class JavaContext extends ClasspathContext {
    def toBinaryName(rep: AbstractFile): String = {
      val name = rep.name
      assert(endsClass(name), name)
      FileUtils.stripClassExtension(name)
    }

    def newClasspath(dir: AbstractFile) = new DirectoryClasspath(dir, this)
  }

  object DefaultJavaContext extends JavaContext

  /** From the source file to its identifier.
   */
  def toSourceName(f: AbstractFile): String = FileUtils.stripSourceExtension(f.name)
}

import Classpath._

/**
 * Represents a package which contains classes and other packages
 */
abstract class Classpath extends ClassFileLookup {
  /**
   * The short name of the package (without prefix)
   */
  def name: String

  /**
   * A String representing the origin of this classpath element, if known.
   * For example, the path of the directory or jar.
   */
  def origin: Option[String] = None

  /** Info which should be propagated to any sub-classpaths.
   */
  def context: ClasspathContext

  /** Lists of entities.
   */
  def classes: IndexedSeq[ClassRepresentation]
  def packages: IndexedSeq[Classpath]
  def sourcepaths: IndexedSeq[AbstractFile]

  /** The entries this classpath is composed of. In class `Classpath` it's just the singleton list containing `this`.
   *  Subclasses such as `MergedClasspath` typically return lists with more elements.
   */
  def entries: IndexedSeq[Classpath] = IndexedSeq(this)

  /** Merge classpath of `platform` and `urls` into merged classpath */
  def mergeUrlsIntoClasspath(urls: URL*): MergedClasspath = {
    // Collect our new jars/directories and add them to the existing set of classpaths
    val allEntries =
      (entries ++
       urls.map(url => context.newClasspath(AbstractFile.getURL(url)))
      ).distinct

    // Combine all of our classpaths (old and new) into one merged classpath
    new MergedClasspath(allEntries, context)
  }

  /**
   * Represents classes which can be loaded with a ClassfileLoader and/or SourcefileLoader.
   */
  case class ClassRep(binary: Option[AbstractFile], source: Option[AbstractFile]) extends ClassRepresentation {
    def name: String = binary match {
      case Some(x)  => context.toBinaryName(x)
      case _        =>
        assert(source.isDefined)
        toSourceName(source.get)
    }
  }

  /** Filters for assessing validity of various entities.
   */
  def validClassFile(name: String): Boolean = context.validClassFile(name)
  def validPackage(name: String): Boolean = context.validPackage(name)
  def validSourceFile(name: String): Boolean = context.validSourceFile(name)

  def splitWhere(str: String, f: Char => Boolean, doDropIndex: Boolean = false): Option[(String, String)] =
    splitAt(str, str indexWhere f, doDropIndex)

  def splitAt(str: String, idx: Int, doDropIndex: Boolean = false): Option[(String, String)] =
    if (idx == -1) None
    else Some((str take idx, str drop (if (doDropIndex) idx + 1 else idx)))

  /**
   * Find a ClassRep given a class name of the form "package.subpackage.ClassName".
   * Does not support nested classes on .NET
   */
  override def findClass(name: String): Option[ClassRepresentation] =
    splitWhere(name, _ == '.', doDropIndex = true) match {
      case Some((pkg, rest)) =>
        val rep = packages find (_.name == pkg) flatMap (_ findClass rest)
        rep map {
          case x: ClassRepresentation => x
          case x            => throw FatalError("Unexpected ClassRep '%s' found searching for name '%s'".format(x, name))
        }
      case _ =>
        classes find (_.name == name)
    }

  override def findClassFile(name: String): Option[AbstractFile] =
    findClass(name) match {
      case Some(ClassRepresentation(Some(x: AbstractFile), _)) => Some(x)
      case _                                        => None
    }

  override def asSourcePathString: String = sourcepaths.mkString(File.pathSeparator)

  def sortString: String = join(split(asClasspathString).sorted: _*)
  override def equals(that: Any): Boolean = that match {
    case x: Classpath  => this.sortString == x.sortString
    case _                => false
  }
  override def hashCode: Int = sortString.hashCode()
}

/**
 * A Classpath containing source files
 */
class SourcePath[T](dir: AbstractFile, val context: ClasspathContext) extends Classpath {
  import FileUtils.AbstractFileOps

  def name: String = dir.name
  override def origin: Option[String] = dir.underlyingSource map (_.path)
  def asURLs: Seq[URL] = dir.toURLs()
  def asClasspathString: String = dir.path
  val sourcepaths: IndexedSeq[AbstractFile] = IndexedSeq(dir)

  private def traverse() = {
    val classBuf   = immutable.Vector.newBuilder[ClassRep]
    val packageBuf = immutable.Vector.newBuilder[SourcePath[T]]
    dir foreach { f =>
      if (!f.isDirectory && validSourceFile(f.name))
        classBuf += ClassRep(None, Some(f))
      else if (f.isDirectory && validPackage(f.name))
        packageBuf += new SourcePath[T](f, context)
    }
    (packageBuf.result(), classBuf.result())
  }

  lazy val (packages, classes) = traverse()
  override def toString: String = "sourcepath: "+ dir.toString()
}

/**
 * A directory (or a .jar file) containing classfiles and packages
 */
class DirectoryClasspath(val dir: AbstractFile, val context: ClasspathContext) extends Classpath {
  import FileUtils.AbstractFileOps

  def name: String = dir.name
  override def origin: Option[String] = dir.underlyingSource map (_.path)
  def asURLs: Seq[URL] = dir.toURLs(default = Seq(new URL(name)))
  def asClasspathString: String = dir.path
  val sourcepaths: IndexedSeq[AbstractFile] = IndexedSeq()

  // calculates (packages, classes) in one traversal.
  private def traverse() = {
    val classBuf   = immutable.Vector.newBuilder[ClassRep]
    val packageBuf = immutable.Vector.newBuilder[DirectoryClasspath]
    dir foreach {
      f =>
        // Optimization: We assume the file was not changed since `dir` called
        // `Path.apply` and categorized existent files as `Directory`
        // or `File`.
        val isDirectory = f match {
          case pf: org.argus.jawa.core.io.PlainFile => pf.givenPath match {
            case _: org.argus.jawa.core.io.Directory => true
            case _: org.argus.jawa.core.io.File      => false
            case _               => f.isDirectory
          }
          case _ =>
            f.isDirectory
        }
        if (!isDirectory && validClassFile(f.name))
          classBuf += ClassRep(Some(f), None)
        else if (isDirectory && validPackage(f.name))
          packageBuf += new DirectoryClasspath(f, context)
    }
    (packageBuf.result(), classBuf.result())
  }

  lazy val (packages, classes) = traverse()
  override def toString: String = "directory classpath: "+ origin.getOrElse("?")
}

class DeltaClasspath(original: MergedClasspath, subst: Map[Classpath, Classpath])
extends MergedClasspath(original.entries map (e => subst getOrElse (e, e)), original.context) {
  // not sure we should require that here. Commented out for now.
  // require(subst.keySet subsetOf original.entries.toSet)
  // We might add specialized operations for computing classes packages here. Not sure it's worth it.
}

/**
 * A classpath unifying multiple class- and sourcepath entries.
 */
class MergedClasspath(
  override val entries: IndexedSeq[Classpath],
  val context: ClasspathContext)
  extends Classpath {

  def this(entries: TraversableOnce[Classpath], context: ClasspathContext) =
    this(entries.toIndexedSeq, context)

  def name: String = entries.head.name
  def asURLs: List[URL] = (entries flatMap (_.asURLs)).toList
  lazy val sourcepaths: IndexedSeq[AbstractFile] = entries flatMap (_.sourcepaths)

  override def origin = Some(entries map (x => x.origin getOrElse x.name) mkString ("Merged(", ", ", ")"))
  override def asClasspathString: String = join(entries map (_.asClasspathString): _*)

  lazy val classes: IndexedSeq[ClassRepresentation] = {
    var count   = 0
    val indices = mutable.HashMap[String, Int]()
    val cls     = new mutable.ArrayBuffer[ClassRepresentation](1024)

    for (e <- entries; c <- e.classes) {
      val name = c.name
      if (indices contains name) {
        val idx      = indices(name)
        val existing = cls(idx)

        if (existing.binary.isEmpty && c.binary.isDefined)
          cls(idx) = ClassRep(binary = c.binary, source = existing.source)
        if (existing.source.isEmpty && c.source.isDefined)
          cls(idx) = ClassRep(binary = existing.binary, source = c.source)
      }
      else {
        indices(name) = count
        cls += c
        count += 1
      }
    }
    cls.toIndexedSeq
  }

  lazy val packages: IndexedSeq[Classpath] = {
    var count   = 0
    val indices = mutable.HashMap[String, Int]()
    val pkg     = new mutable.ArrayBuffer[Classpath](256)

    for (e <- entries; p <- e.packages) {
      val name = p.name
      if (indices contains name) {
        val idx  = indices(name)
        pkg(idx) = addPackage(pkg(idx), p)
      }
      else {
        indices(name) = count
        pkg += p
        count += 1
      }
    }
    pkg.toIndexedSeq
  }

  private def addPackage(to: Classpath, pkg: Classpath) = {
    val newEntries: IndexedSeq[Classpath] = to match {
      case cp: MergedClasspath => cp.entries :+ pkg
      case _                      => IndexedSeq(to, pkg)
    }
    new MergedClasspath(newEntries, context)
  }

  def show() {
    println("Classpath %s has %d entries and results in:\n".format(name, entries.size))
    asClasspathString split ':' foreach (x => println("  " + x))
  }

  override def toString: String = "merged classpath "+ entries.mkString("(", "\n", ")")
}

/**
 * The classpath when compiling with target:jvm. Binary files (classfiles) are represented
 * as AbstractFile. ZipArchive is used to view zip/jar archives as directories.
 */
class JavaClasspath(
  containers: IndexedSeq[Classpath],
  context: JavaContext)
extends MergedClasspath(containers, context) { }
