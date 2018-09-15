/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.compile.io

import java.io.IOException

object ErrorHandling
{
  def translate[T](msg: => String)(f: => T): T =
    try { f }
    catch {
      case e: IOException => throw new TranslatedIOException(msg + e.toString, e)
      case e: Exception => throw new TranslatedException(msg + e.toString, e)
    }

  def wideConvert[T](f: => T): Either[Throwable, T] =
    try { Right(f) }
    catch
    {
      case ex @ (_: Exception | _: StackOverflowError) => Left(ex)
      case err @ (_: ThreadDeath | _: VirtualMachineError) => throw err
      case x: Throwable => Left(x)
    }

  def convert[T](f: => T): Either[Exception, T] =
    try { Right(f) }
    catch { case e: Exception => Left(e) }

  def reducedToString(e: Throwable): String =
    if(e.getClass == classOf[RuntimeException])
    {
      val msg = e.getMessage
      if(msg == null || msg.isEmpty) e.toString else msg
    }
    else
      e.toString
}
sealed class TranslatedException private[io](msg: String, cause: Throwable) extends RuntimeException(msg, cause) {
  override def toString: String = msg
}
final class TranslatedIOException private[io](msg: String, cause: IOException) extends TranslatedException(msg, cause)
