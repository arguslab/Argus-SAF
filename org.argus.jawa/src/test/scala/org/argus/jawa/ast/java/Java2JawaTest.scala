/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.java

import java.lang.reflect.InvocationTargetException

import org.argus.jawa.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core._
import org.argus.jawa.core.io.{JavaSourceFile, PlainFile}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class Java2JawaTest extends FlatSpec with Matchers {

  val DEBUG = true

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/java/parser/as/Assert1.java" should "throw AssertionError" in {
    an[AssertionError] should be thrownBy run("/java/parser/as/Assert1.java")
  }

//  "/java/parser/cons/ConstructorWithSuper.java" produce (1)

  class TestFile(file: String) {
    def produce(tp: Any): Unit = {
      file should "produce expected result" in {
        val r = run(file)
        assert(r == tp)
      }
    }
  }

  def run(file: String): Any = {
    val fileUri = FileUtil.toUri(getClass.getResource(file).getPath)
    val sf = new JavaSourceFile(new PlainFile(FileUtil.toFile(fileUri)))
    val global = new Global("test", new PrintReporter(MsgLevel.INFO))
    global.setJavaLib(getClass.getResource("/libs/rt.jar").getPath)
    global.load(FileUtil.toUri(getClass.getResource("/java/parser").getPath), Constants.JAVA_FILE_EXT, NoLibraryAPISummary.isLibraryClass)
    val j2j = new Java2Jawa(global, sf)
    val cu = j2j.process
    val css = new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
    val ccl: CustomClassLoader = new CustomClassLoader()
    var result: Any = null
    css foreach { case (typ, bytecodes) =>
      try{
        val c = ccl.loadClass(typ.name, bytecodes)
        result = c.getMethod("main").invoke(null)
      } catch {
        case ite: InvocationTargetException =>
          throw ite.getTargetException
        case ilv: java.lang.VerifyError =>
          throw new RuntimeException(ilv.getMessage)
      }
    }
    result
  }
}
