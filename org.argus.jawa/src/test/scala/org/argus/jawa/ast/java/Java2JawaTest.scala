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
import org.argus.jawa.core.io.JavaSourceFile
import org.argus.jawa.core.util.FileUtil
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class Java2JawaTest extends FlatSpec with Matchers {

  val DEBUG = true

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/java/parser/as/Assert1.java" should "throw AssertionError" in {
    an[AssertionError] should be thrownBy run("/java/parser/as/Assert1.java", loadpkg = false)
  }

  "/java/parser/cons/StaticInitializer.java" produce (1)

  "/java/parser/cons/StaticInitializerMixed.java" produce (2)

  "/java/parser/cons/StaticInitializerWithStaticBlock.java" produce (1)

  "/java/parser/cons/ConstructorWithoutSuper.java" produce (1)

  "/java/parser/cons/ConstructorWithSuper.java" produce (1)

//  "/java/parser/cons/InnerConstructor.java" produce (1)

  "/java/parser/expr/arraycreationexpr/ArrayCreationComplex.java" produce (11)

  "/java/parser/expr/arraycreationexpr/ArrayCreationInit.java" produce (3)

  "/java/parser/expr/arraycreationexpr/ArrayCreationNoInit.java" produce (2)

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

  "/java/parser/expr/castexpr/CastObject.java" produce (1)

  "/java/parser/expr/classexpr/ClassExpression.java" produce (true)

  "/java/parser/expr/conditionalexpr/ConditionalExpr.java" produce (3)

  "/java/parser/expr/instanceofexpr/InstanceOfExpression.java" produce (true)

  "/java/parser/expr/unaryexpr/BITWISE_COMPLEMENT.java" produce (-9)

  "/java/parser/expr/unaryexpr/Complex.java" produce (-3)

  "/java/parser/expr/unaryexpr/LOGICAL_COMPLEMENT.java" produce (false)

  "/java/parser/expr/unaryexpr/MINUS.java" produce (-1)

  "/java/parser/expr/unaryexpr/PLUS.java" produce (1)

  "/java/parser/expr/unaryexpr/POSTFIX_DECREMENT.java" produce (1)

  "/java/parser/expr/unaryexpr/POSTFIX_INCREMENT.java" produce (1)

  "/java/parser/expr/unaryexpr/PREFIX_DECREMENT.java" produce (0)

  "/java/parser/expr/unaryexpr/PREFIX_INCREMENT.java" produce (2)

  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive.java" produce (3)

  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive2.java" produce (3D)

  "/java/parser/imports/ImportsTest.java" produce (7, true)

  "/java/parser/imports/StaticImportsTest.java" produce (5, true)

  class TestFile(file: String) {
    def produce(tp: Any, loadpkg: Boolean = false): Unit = {
      file should "produce expected result" in {
        val r = run(file, loadpkg)
        assert(r == tp)
      }
    }
  }

  def run(file: String, loadpkg: Boolean): Any = {
    val path = file.substring(0, file.lastIndexOf("/"))
    val className = file.substring(6, file.length - 5).replace("/", ".")
    val global = new Global("test", new PrintReporter(MsgLevel.INFO))
    global.setJavaLib(getClass.getResource("/libs/rt.jar").getPath)
    val map = if(loadpkg) {
      global.load(FileUtil.toUri(getClass.getResource(path).getPath), Constants.JAVA_FILE_EXT, NoLibraryAPISummary.isLibraryClass)
    } else {
      global.load(FileUtil.toUri(getClass.getResource(file).getPath), NoLibraryAPISummary.isLibraryClass)
    }
    val ccl: CustomClassLoader = new CustomClassLoader()
    map.foreach {
      case (_, sf) =>
        val jsf = sf.asInstanceOf[JavaSourceFile]
        val j2j = new Java2Jawa(global, jsf)
        val cu = j2j.process(true)
        println(cu.toCode)
        val css = new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
        val pw = new PrintWriter(System.out)
        css foreach { case (ctyp, bytecodes) =>
          JavaByteCodeGenerator.outputByteCodes(pw, bytecodes)
          ccl.loadClass(ctyp.name, bytecodes)
        }
    }

    var result: Any = null

    try{
      val c = ccl.loadClass(className)
      result = c.getMethod("main").invoke(null)
    } catch {
      case ite: InvocationTargetException =>
        throw ite.getTargetException
      case ilv: java.lang.VerifyError =>
        throw new RuntimeException(ilv.getMessage)
    }
    result
  }
}
