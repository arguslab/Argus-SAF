/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.io

import java.io.{BufferedInputStream, BufferedReader, InputStream, InputStreamReader, Closeable => JCloseable}
import java.net.URL

import org.argus.jawa.core.io.Path.fail

import scala.collection.mutable.ArrayBuffer
import scala.io.{BufferedSource, Codec, Source}

/** Traits for objects which can be represented as Streams.
 *
 *  @author Paul Phillips
 *  @since  2.8
 *
 *  ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
 */
object Streamable {
  /** Traits which can be viewed as a sequence of bytes.  Source types
   *  which know their length should override def length: Long for more
   *  efficient method implementations.
   *
   *  ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
   */
  trait Bytes {
    def inputStream(): InputStream
    def length: Long = -1

    def bufferedInput() = new BufferedInputStream(inputStream())
    def bytes(): Iterator[Byte] = bytesAsInts() map (_.toByte)
    def bytesAsInts(): Iterator[Int] = {
      val in = bufferedInput()
      Iterator continually in.read() takeWhile (_ != -1)
    }

    /** This method aspires to be the fastest way to read
     *  a stream of known length into memory.
     */
    def toByteArray: Array[Byte] = {
      // if we don't know the length, fall back on relative inefficiency
      if (length == -1L)
        return (new ArrayBuffer[Byte]() ++= bytes()).toArray

      val arr = new Array[Byte](length.toInt)
      val len = arr.length
      lazy val in = bufferedInput()
      var offset = 0

      def loop() {
        if (offset < len) {
          val read = in.read(arr, offset, len - offset)
          if (read >= 0) {
            offset += read
            loop()
          }
        }
      }
      try loop()
      finally in.close()

      if (offset == arr.length) arr
      else fail("Could not read entire source (%d of %d bytes)".format(offset, len))
    }
  }

  /** For objects which can be viewed as Chars.
   *
   * ''Note:  This library is considered experimental and should not be used unless you know what you are doing.''
   */
  trait Chars extends Bytes {
    /** Calls to methods requiring byte<->char transformations should be offered
     *  in a form which allows specifying the codec.  When it is not specified,
     *  the one discovered at creation time will be used, which will always find the
     *  one in scala.io.Codec if no other is available.  This can be overridden
     *  to use a different default.
     */
    def creationCodec: Codec = implicitly[Codec]

    def chars(codec: Codec): BufferedSource = Source.fromInputStream(inputStream())(codec)

    def lines(): Iterator[String] = lines(creationCodec)
    def lines(codec: Codec): Iterator[String] = chars(codec).getLines()

    /** Obtains an InputStreamReader wrapped around a FileInputStream.
     */
    def reader(codec: Codec): InputStreamReader = new InputStreamReader(inputStream(), codec.charSet)

    /** Wraps a BufferedReader around the result of reader().
     */
    def bufferedReader(): BufferedReader = bufferedReader(creationCodec)
    def bufferedReader(codec: Codec) = new BufferedReader(reader(codec))

    /** Creates a BufferedReader and applies the closure, automatically closing it on completion.
     */
    def applyReader[T](f: BufferedReader => T): T = {
      val in = bufferedReader()
      try f(in)
      finally in.close()
    }

    /** Convenience function to import entire file into a String.
     */
    def slurp(): String = slurp(creationCodec)
    def slurp(codec: Codec): String = {
      val src = chars(codec)
      try src.mkString finally src.close()  // Always Be Closing
    }
  }

  /** Call a function on something Closeable, finally closing it. */
  def closing[T <: JCloseable, U](stream: T)(f: T => U): U =
    try f(stream)
    finally stream.close()

  def bytes(is: => InputStream): Array[Byte] =
    new Bytes {
      def inputStream(): InputStream = is
    }.toByteArray

  def slurp(is: => InputStream)(implicit codec: Codec): String =
    new Chars { def inputStream(): InputStream = is } slurp codec

  def slurp(url: URL)(implicit codec: Codec): String =
    slurp(url.openStream())
}
