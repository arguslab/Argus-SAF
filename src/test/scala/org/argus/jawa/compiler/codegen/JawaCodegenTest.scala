/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.codegen

import java.io.{File, PrintWriter}
import java.lang.reflect.InvocationTargetException

import org.argus.jawa.compiler.lexer.JawaLexer
import org.argus.jawa.compiler.parser.JawaParser
import org.argus.jawa.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.io.{FgSourceFile, PlainFile, SourceFile}
import org.scalatest._

class JawaCodegenTest extends FlatSpec with Matchers {

  "Generate code" should "not throw an exception on ArrayAccess1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayAccess1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayAccess2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayAccess2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayAccess3" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayAccess3.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayCopy" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayCopy.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayFill1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayFill1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayFill2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayFill2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ArrayLength1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/array/ArrayLength1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Cmp1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/cmp/Cmp1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Cmp2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/cmp/Cmp2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ConstClass1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/constclass/ConstClass1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on ConstClass2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/constclass/ConstClass2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on DoubleLong1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/doublelong/DoubleLong1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Exceptions1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/exception/Exceptions1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Exceptions2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/exception/Exceptions2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Exceptions3" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/exception/Exceptions3.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "throw an exception on Exceptions4" in {
    an [RuntimeException] should be thrownBy {
      val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/exception/Exceptions4.jawa").getPath)))
      genCode(jf)
    }
  }

  "Generate code" should "not throw an exception on FieldAccess1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/field/FieldAccess1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on FieldAccess2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/field/FieldAccess2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Instanceof1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/instance/Instanceof1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Instanceof2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/instance/Instanceof2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on IfJump1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/jump/IfJump1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on IfJump2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/jump/IfJump2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on SwitchJump1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/jump/SwitchJump1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on SwitchJump2" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/jump/SwitchJump2.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on Monitor1" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/monitor/Monitor1.jawa").getPath)))
    genCode(jf)
  }

  "Generate code" should "not throw an exception on IJawa" in {
    val jf = new FgSourceFile(new PlainFile(new File(getClass.getResource("/jawa_typed/interface/IJawa.jawa").getPath)))
    printCode(jf)
  }

  val reporter = new DefaultReporter
  private def parser(s: Either[String, SourceFile]) = new JawaParser(JawaLexer.tokenise(s, reporter).toArray, reporter)

  private def genCode(s: SourceFile) = {
    val newcode = s.code
    val cu = parser(Left(newcode)).compilationUnit(true)
    val css = new JavaByteCodeGenerator("1.8").generate(cu)
    val ccl: CustomClassLoader = new CustomClassLoader()
    val pw = new PrintWriter(System.out)
    css foreach {
      case (typ, bytecodes) =>
        JavaByteCodeGenerator.outputByteCodes(pw, bytecodes)
        try{
          val c = ccl.loadClass(typ.name, bytecodes)
          val r = c.getMethod("main").invoke(null)
          println("result: " + r)
        } catch {
          case ite: InvocationTargetException =>
            throw ite.getTargetException
          case ilv: java.lang.VerifyError =>
            throw new RuntimeException(ilv.getMessage)
        }
    }
  }

  private def printCode(s: SourceFile) = {
    val newcode = s.code
    val cu = parser(Left(newcode)).compilationUnit(true)
    val css = new JavaByteCodeGenerator("1.8").generate(cu)
    val pw = new PrintWriter(System.out)
    css foreach {
      case (_, bytecodes) =>
        JavaByteCodeGenerator.outputByteCodes(pw, bytecodes)
    }
  }
}
