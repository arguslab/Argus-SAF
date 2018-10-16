/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.compile.io

import java.io.{Closeable, FileInputStream, FileOutputStream, InputStream, OutputStream, File => JavaFile}
import java.io.{BufferedInputStream, BufferedOutputStream, InputStreamReader, OutputStreamWriter}
import java.io.{BufferedReader, BufferedWriter}
import java.util.zip.GZIPInputStream
import java.net.URL
import java.nio.channels.FileChannel
import java.nio.charset.Charset
import java.util.jar.{JarFile, JarInputStream, JarOutputStream}
import java.util.zip.{GZIPOutputStream, ZipEntry, ZipFile, ZipInputStream, ZipOutputStream}

import ErrorHandling.translate

import scala.reflect.{Manifest => SManifest}

abstract class Using[Source, T]
{
  protected def open(src: Source): T
  def apply[R](src: Source)(f: T => R): R =
  {
    val resource = open(src)
    try { f(resource) }
    finally { close(resource) }
  }
  protected def close(out: T): Unit
}
abstract class WrapUsing[Source, T](implicit srcMf: SManifest[Source], targetMf: SManifest[T]) extends Using[Source, T]
{
  protected def label[S](m: SManifest[S]): String = m.runtimeClass.getSimpleName
  protected def openImpl(source: Source): T
  protected final def open(source: Source): T =
    translate("Error wrapping " + label(srcMf) + " in " + label(targetMf) + ": ") { openImpl(source) }
}
trait OpenFile[T] extends Using[JavaFile, T]
{
  protected def openImpl(file: JavaFile): T
  protected final def open(file: JavaFile): T =
  {
    val parent = file.getParentFile
    if(parent != null)
      IO.createDirectory(parent)
    openImpl(file)
  }
}
object Using
{
  def wrap[Source, T<: Closeable](openF: Source => T)(implicit srcMf: SManifest[Source], targetMf: SManifest[T]): Using[Source,T] =
    wrap(openF, closeCloseable)
  def wrap[Source, T](openF: Source => T, closeF: T => Unit)(implicit srcMf: SManifest[Source], targetMf: SManifest[T]): Using[Source,T] =
    new WrapUsing[Source, T]
    {
      def openImpl(source: Source): T = openF(source)
      def close(t: T): Unit = closeF(t)
    }

  def resource[Source, T <: Closeable](openF: Source => T): Using[Source,T] =
    resource(openF, closeCloseable)
  def resource[Source, T](openF: Source => T, closeF: T => Unit): Using[Source,T] =
    new Using[Source,T]
    {
      def open(s: Source): T = openF(s)
      def close(s: T): Unit = closeF(s)
    }
  def file[T <: Closeable](openF: JavaFile => T): OpenFile[T] = file(openF, closeCloseable)
  def file[T](openF: JavaFile => T, closeF: T => Unit): OpenFile[T] =
    new OpenFile[T]
    {
      def openImpl(file: JavaFile): T = openF(file)
      def close(t: T): Unit = closeF(t)
    }
  private def closeCloseable[T <: Closeable]: T => Unit = _.close()

  def bufferedOutputStream: Using[OutputStream, BufferedOutputStream] = wrap((out: OutputStream) => new BufferedOutputStream(out) )
  def bufferedInputStream: Using[InputStream, BufferedInputStream] = wrap((in: InputStream) => new BufferedInputStream(in) )
  def fileOutputStream(append: Boolean = false): OpenFile[BufferedOutputStream] = file(f => new BufferedOutputStream(new FileOutputStream(f, append)))
  def fileInputStream: OpenFile[BufferedInputStream] = file(f => new BufferedInputStream(new FileInputStream(f)))
  def urlInputStream: Using[URL, BufferedInputStream] = resource((u: URL) => translate("Error opening " + u + ": ")(new BufferedInputStream(u.openStream)))
  def fileOutputChannel: OpenFile[FileChannel] = file(f => new FileOutputStream(f).getChannel)
  def fileInputChannel: OpenFile[FileChannel] = file(f => new FileInputStream(f).getChannel)
  def fileWriter(charset: Charset = IO.utf8, append: Boolean = false): OpenFile[BufferedWriter] =
    file(f => new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f, append), charset)) )
  def fileReader(charset: Charset): OpenFile[BufferedReader] = file(f => new BufferedReader(new InputStreamReader(new FileInputStream(f), charset)) )
  def urlReader(charset: Charset): Using[URL, BufferedReader] = resource((u: URL) => new BufferedReader(new InputStreamReader(u.openStream, charset)))
  def jarFile(verify: Boolean): OpenFile[JarFile] = file(f => new JarFile(f, verify), (_: JarFile).close())
  def zipFile: OpenFile[ZipFile] = file(f => new ZipFile(f), (_: ZipFile).close())
  def streamReader: Using[(InputStream, Charset), InputStreamReader] = wrap{ (_: (InputStream, Charset)) match { case (in, charset) => new InputStreamReader(in, charset) } }
  def gzipInputStream: Using[InputStream, GZIPInputStream] = wrap((in: InputStream) => new GZIPInputStream(in, 8192) )
  def zipInputStream: Using[InputStream, ZipInputStream] = wrap((in: InputStream) => new ZipInputStream(in))
  def zipOutputStream: Using[OutputStream, ZipOutputStream] = wrap((out: OutputStream) => new ZipOutputStream(out))
  def gzipOutputStream: Using[OutputStream, GZIPOutputStream] = wrap((out: OutputStream) => new GZIPOutputStream(out, 8192), (_: GZIPOutputStream).finish())
  def jarOutputStream: Using[OutputStream, JarOutputStream] = wrap((out: OutputStream) => new JarOutputStream(out))
  def jarInputStream: Using[InputStream, JarInputStream] = wrap((in: InputStream) => new JarInputStream(in))
  def zipEntry(zip: ZipFile): Using[ZipEntry, InputStream] = resource((entry: ZipEntry) =>
    translate("Error opening " + entry.getName + " in " + zip + ": ") { zip.getInputStream(entry) } )
}
