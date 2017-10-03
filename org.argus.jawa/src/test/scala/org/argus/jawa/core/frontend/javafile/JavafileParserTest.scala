/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.frontend.javafile

import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.io.{DefaultSourceFile, PlainFile}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class JavafileParserTest extends FlatSpec with Matchers {

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/java/parser/HelloWorld.java" produce ("")


  class TestFile(file: String) {
    def produce(tp: String): Unit = {
      file should "produce expected result" in {
        val fileUri = FileUtil.toUri(getClass.getResource(file).getPath)
        val sf = new DefaultSourceFile(new PlainFile(FileUtil.toFile(fileUri)))
        JavafileParser.parse(sf, new DefaultReporter)
      }
    }
  }
}
