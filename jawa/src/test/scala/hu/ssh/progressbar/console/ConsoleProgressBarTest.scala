/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.console

import java.io.{ByteArrayOutputStream, PrintStream}

import com.google.common.base.{Splitter, Strings}
import com.google.common.collect.Iterables
import hu.ssh.progressbar.ConsoleProgressBar
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 5/2/17.
  */
class ConsoleProgressBarTest extends FlatSpec with Matchers {
  "ProgressBar" should "output as expected" in {
    val outputstream = new ByteArrayOutputStream
    try {
      val progressBar = ConsoleProgressBar.on(new PrintStream(outputstream)).withFormat(":percent")
      progressBar.tick(0)
      assert(getLastOutput(outputstream.toString) == "  0.00")
      progressBar.tick(25)
      assert(getLastOutput(outputstream.toString) == " 25.00")
      progressBar.tick(30)
      assert(getLastOutput(outputstream.toString) == " 55.00")
      progressBar.tick(44)
      assert(getLastOutput(outputstream.toString) == " 99.00")
      progressBar.tickOne()
      assert(getLastOutput(outputstream.toString) == "100.00")
    } finally outputstream.close()
  }

  private def getLastOutput(string: String): String = {
    if (Strings.isNullOrEmpty(string)) return string
    val outputs = Splitter.on(ConsoleProgressBar.CARRIAGE_RETURN).omitEmptyStrings.split(string)
    Iterables.getLast(outputs)
  }
}
