/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.serialization

import java.io.StringWriter

import org.argus.jawa.core.Signature
import org.argus.jawa.core.util._
import org.argus.jnsaf.analysis.NativeMethodHandler
import org.json4s.{Formats, NoTypeHints}
import org.json4s.native.Serialization
import org.json4s.native.Serialization.write
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 6/20/17.
  */
class SerializationTest extends FlatSpec with Matchers {
  "Statistic Serialization" should "produce as expected" in {
    val data: MMap[String, MMap[String, IList[String]]] = mmapEmpty
    val sig: Signature = new Signature("Lmy/Class;.foo:(Ljava/lang/String;)V")
    val sig2: Signature = new Signature("Lmy/Class;.bar:(Ljava/lang/String;IJ)V")
    val soFile: String = "/my/path/to/so/file.so"
    data(soFile) = mmapEmpty

    val funcName = NativeMethodHandler.getJNIFunctionName(sig, overload = false)
    val params = sig.getParameterTypes.map(_.jawaName)
    data(soFile)(funcName) = params

    val funcName2 = NativeMethodHandler.getJNIFunctionName(sig2, overload = false)
    val params2 = sig2.getParameterTypes.map(_.jawaName)
    data(soFile)(funcName2) = params2

    val oapk = new StringWriter()
    implicit val formats: Formats = Serialization.formats(NoTypeHints)
    try {
      write(data, oapk)
      val json = oapk.getBuffer.toString
      println(json)
    } catch {
      case e: Exception =>
        throw e
    } finally {
      oapk.flush()
      oapk.close()
    }
  }
}
