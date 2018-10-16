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

import scala.language.postfixOps
import Classpath.{DefaultJavaContext, JavaContext, split}
import java.net.URL

import org.argus.jawa.core.ClasspathRepresentationType

object PathResolver {
  // Imports property/environment functions which suppress security exceptions.
  import scala.compat.Platform.EOL

  implicit class MkLines(val t: TraversableOnce[_]) extends AnyVal {
    def mkLines: String = t.mkString("", EOL, EOL)
    def mkLines(header: String, indented: Boolean = false, embraced: Boolean = false): String = {
      val space = "\u0020"
      val sep = if (indented) EOL + space * 2 else EOL
      val (lbrace, rbrace) = if (embraced) (space + "{", EOL + "}") else ("", "")
      t.mkString(header + lbrace + sep, sep, rbrace + EOL)
    }
  }
  implicit class AsLines(val s: String) extends AnyVal {
    // sm"""...""" could do this in one pass
    def asLines: String = s.trim.stripMargin.lines.mkLines
  }

  /** pretty print class path */
  def ppcp(s: String): String = split(s) match {
    case Nil      => ""
    case Seq(x)   => x
    case xs       => xs.mkString(EOL, EOL, "")
  }

  // used in PathResolver constructor
  private object NoImplClassJavaContext extends JavaContext {
    override def isValidName(name: String): Boolean =
      name.endsWith(".class")
  }

  /** If there are arguments, show those in Calculated as if those options had been
   *  given to a jawa runner.
   */
  def main(args: Array[String]): Unit = {
    if(args.length != 2) {
      System.err.println("usage: -javaLib path")
    }
    val javaLib = args(1)
    val pr = PathResolverFactory.create(ClasspathRepresentationType.Flat, javaLib)
  
    pr.result match {
      case cp: JavaClasspath =>
        cp.show()
      case cp: AggregateFlatClasspath =>
        println(s"ClassPath has ${cp.aggregates.size} entries and results in:\n${cp.asClasspathStrings}")
    }
  }
}

trait PathResolverResult {
  def result: ClassFileLookup

  def resultAsURLs: Seq[URL] = result.asURLs
}

abstract class PathResolverBase[BaseClassPathType <: ClassFileLookup, ResultClassPathType <: BaseClassPathType]
(classPathFactory: ClasspathFactory[BaseClassPathType], javaLib: String)
  extends PathResolverResult {

  import PathResolver.{ AsLines, ppcp }

  /** Calculated values based on any given command line options, falling back on
   *  those in Defaults.
   */
  object Calculated {
    def javaLibClassPath: String = javaLib

    /** Against my better judgment, giving in to martin here and allowing
     *  CLASSPATH to be used automatically.  So for the user-specified part
     *  of the classpath:
     *
     *  - If -classpath or -cp is given, it is that
     *  - Otherwise, if CLASSPATH is set, it is that
     *  - If neither of those, then "." is used.
     */
    def userClassPath: String = sys.env.getOrElse("CLASSPATH", ".")

    import classPathFactory._

    // Assemble the elements!
    def basis: List[Traversable[BaseClassPathType]] = List[Traversable[BaseClassPathType]](
      classesInExpandedPath(javaLibClassPath)     // 1. The Java lib class path.
    )

    lazy val containers: List[BaseClassPathType] = basis.flatten.distinct

    override def toString: String = s"""
      |object Calculated {\
      |  javaUserClassPath    = ${ppcp(javaLibClassPath)}
      |  userClassPath        = ${ppcp(userClassPath)}
      |}""".asLines
  }
  
  def containers: List[BaseClassPathType] = Calculated.containers

  def result: ResultClassPathType = {
    val cp = computeResult()
    cp
  }

  protected def computeResult(): ResultClassPathType
}

class PathResolver(context: JavaContext, javaLib: String)
  extends PathResolverBase[Classpath, JavaClasspath](context, javaLib) {

  def this(javaLib: String) =
    this(
      if (false) PathResolver.NoImplClassJavaContext
      else DefaultJavaContext,
      javaLib)

  override protected def computeResult(): JavaClasspath =
    new JavaClasspath(containers.toIndexedSeq, context)
}

class FlatClasspathResolver(flatClassPathFactory: ClasspathFactory[FlatClasspath], javaLib: String)
  extends PathResolverBase[FlatClasspath, AggregateFlatClasspath](flatClassPathFactory, javaLib) {

  def this(javaLib: String) = this(new FlatClasspathFactory(), javaLib)

  override protected def computeResult(): AggregateFlatClasspath = AggregateFlatClasspath(containers.toIndexedSeq)
}

object PathResolverFactory {

  def create(value: ClasspathRepresentationType.Value, javaLib: String): PathResolverResult =
    value match {
      case ClasspathRepresentationType.Flat => new FlatClasspathResolver(javaLib)
      case ClasspathRepresentationType.Recursive => new PathResolver(javaLib)
    }
}
