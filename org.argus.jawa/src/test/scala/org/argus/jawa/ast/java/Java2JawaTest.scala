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

import java.io.PrintWriter
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

  "/java/parser/cons/StaticInitializer.java" produce (1)

  "/java/parser/cons/StaticInitializerMixed.java" produce (2)

  "/java/parser/cons/StaticInitializerWithStaticBlock.java" produce (1)

  "/java/parser/cons/ConstructorWithoutSuper.java" produce (1)

  "/java/parser/cons/ConstructorWithSuper.java" produce (1)

//  "/java/parser/cons/InnerConstructor.java" produce (1)

  "/java/parser/expr/assignexpr/AND.java" produce (0)

  "/java/parser/expr/assignexpr/DIVIDE.java" produce (3)

  "/java/parser/expr/assignexpr/LEFT_SHIFT.java" produce (4)

  "/java/parser/expr/assignexpr/MINUS.java" produce (-1)

  "/java/parser/expr/assignexpr/MULTIPLY.java" produce (6)

  "/java/parser/expr/assignexpr/OR.java" produce (3)

  "/java/parser/expr/assignexpr/PLUS.java" produce (3)

  "/java/parser/expr/assignexpr/REMAINDER.java" produce (0)

  "/java/parser/expr/assignexpr/SIGNED_RIGHT_SHIFT.java" produce (2)

  "/java/parser/expr/assignexpr/UNSIGNED_RIGHT_SHIFT.java" produce (2)

  "/java/parser/expr/assignexpr/XOR.java" produce (3)

  "/java/parser/expr/binaryexpr/AND.java" produce (false)

  "/java/parser/expr/binaryexpr/BINARY_AND.java" produce (0)

  "/java/parser/expr/binaryexpr/BINARY_OR.java" produce (1)

  "/java/parser/expr/binaryexpr/DIVIDE.java" produce (0)

  "/java/parser/expr/binaryexpr/EQUALS.java" produce (false)

  "/java/parser/expr/binaryexpr/GREATER.java" produce (false)

  "/java/parser/expr/binaryexpr/GREATER_EQUALS.java" produce (true)

  "/java/parser/expr/binaryexpr/LEFT_SHIFT.java" produce (2)

  "/java/parser/expr/binaryexpr/LESS.java" produce (true)

  "/java/parser/expr/binaryexpr/LESS_EQUALS.java" produce (true)

  "/java/parser/expr/binaryexpr/MINUS.java" produce (0)

  "/java/parser/expr/binaryexpr/MULTIPLY.java" produce (6)

  "/java/parser/expr/binaryexpr/NOT_EQUALS.java" produce (true)

  "/java/parser/expr/binaryexpr/OR.java" produce (true)

  "/java/parser/expr/binaryexpr/PLUS.java" produce (3)

  "/java/parser/expr/binaryexpr/REMAINDER.java" produce (1)

  "/java/parser/expr/binaryexpr/SIGNED_RIGHT_SHIFT.java" produce (1)

  "/java/parser/expr/binaryexpr/UNSIGNED_RIGHT_SHIFT.java" produce (1)

  "/java/parser/expr/binaryexpr/XOR.java" produce (true)

  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive.java" produce (3)

  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive2.java" produce (3D)

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
    val global = new Global("test", new PrintReporter(MsgLevel.INFO))
    global.setJavaLib(getClass.getResource("/libs/rt.jar").getPath)
    global.load(FileUtil.toUri(getClass.getResource("/java/parser").getPath), Constants.JAVA_FILE_EXT, NoLibraryAPISummary.isLibraryClass)
    val sf = new JavaSourceFile(global, new PlainFile(FileUtil.toFile(fileUri)))
    val j2j = new Java2Jawa(global, sf)
    val cu = j2j.process(true)
    println(cu.toCode)
    val css = new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
    val ccl: CustomClassLoader = new CustomClassLoader()
    var result: Any = null
//    val pw = new PrintWriter(System.out)
//    css foreach { case (_, bytecodes) =>
//      JavaByteCodeGenerator.outputByteCodes(pw, bytecodes)
//    }
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
