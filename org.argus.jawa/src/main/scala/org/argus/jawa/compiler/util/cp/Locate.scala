/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.util.cp

import java.io.File
import java.util.zip.ZipFile
import java.util.zip.ZipException
import Function.const

import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object Locate
{
  type DefinesClass = File => String => Boolean

  /** Right(src) provides the value for the found class
  * Left(true) means that the class was found, but it had no associated value
  * Left(false) means that the class was not found */
  def value[S](classpath: Seq[File], get: File => String => Option[S]): String => Either[Boolean, S] =
  {
    val gets = classpath.toStream.map(getValue(get))
    className => find(className, gets)
  }
  
  def find[S](name: String, gets: Stream[String => Either[Boolean, S]]): Either[Boolean, S] =
    if(gets.isEmpty)
      Left(false)
    else
      gets.head(name) match
      {
        case Left(false) => find(name, gets.tail)
        case x => x
      }
  
  /** Returns a function that searches the provided class path for
  * a class name and returns the entry that defines that class.*/
  def entry(classpath: Seq[File], f: DefinesClass): String => Option[File] =
  {
    val entries = classpath.toStream.map { entry => (entry, f(entry)) }
    className => entries collect { case (entry, defines) if defines(className) => entry } headOption
  }
  def resolve(f: File, className: String): File = if(f.isDirectory) classFile(f, className) else f
  
  def getValue[S](get: File => String => Option[S])(entry: File): String => Either[Boolean, S] = 
  {
    val defClass = definesClass(entry)
    val getF = get(entry)
    className => if(defClass(className)) getF(className).toRight(true) else Left(false)
  }
    
  def definesClass(entry: File): String => Boolean =
    if(entry.isDirectory)
      directoryDefinesClass(entry)
    else if(entry.exists && ClasspathUtilities.isArchive(entry, contentFallback=true))
      jarDefinesClass(entry)
    else
      const(false)
  
  def jarDefinesClass(entry: File): String => Boolean =
  {
    import collection.JavaConversions._
    val jar = try { new ZipFile(entry, ZipFile.OPEN_READ) } catch {
      // ZipException doesn't include the file name :(
      case e: ZipException => throw new RuntimeException("Error opening zip file: " + entry.getName, e)
    }
    val entries = try { jar.entries.map(e => toClassName(e.getName)).toSet } finally { jar.close() }
    entries.contains
  }
  
  def toClassName(entry: String): String =
    entry.stripSuffix(ClassExt).replace('/', '.')
  
  val ClassExt = ".class"
    
  def directoryDefinesClass(entry: File): String => Boolean =
    className => classFile(entry, className).isFile
    
  def classFile(baseDir: File, className: String): File = 
  {
    val (pkg, name) = components(className)
    val dir = subDirectory(baseDir, pkg)
    new File(dir, name + ClassExt)
  }
    
  def subDirectory(base: File, parts: Seq[String]): File =
    (base /: parts) ( (b, p) => new File(b,p) )
    
  def components(className: String): (Seq[String], String) =
  {
    assume(!className.isEmpty)
    val parts = className.split("\\.")
    if(parts.length == 1) (Nil, parts(0)) else (parts.init, parts.last)
  }
}
