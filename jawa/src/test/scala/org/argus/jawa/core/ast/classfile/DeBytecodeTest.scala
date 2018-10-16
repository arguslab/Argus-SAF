/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import java.io.PrintWriter
import java.lang.reflect.InvocationTargetException

import org.argus.jawa.core.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.core._
import org.argus.jawa.core.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.PlainFile
import org.argus.jawa.core.util._
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class DeBytecodeTest extends FlatSpec with Matchers {

  val DEBUG = true

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

  "/class/parser/cons/StaticInitializer.class" produce_same()

  "/class/parser/cons/StaticInitializerMixed.class" produce_same()

  "/class/parser/cons/StaticInitializerWithStaticBlock.class" produce_same()

  "/class/parser/cons/ConstructorWithoutSuper.class" produce_same()

  "/class/parser/cons/ConstructorWithSuper.class" produce_same()

  "/class/parser/cons/InnerConstructor.class" produce_same "/class/parser/cons/InnerConstructor$Inner.class"

  "/class/parser/expr/arraycreationexpr/ArrayCreationComplex.class" produce_same()

  "/class/parser/expr/arraycreationexpr/ArrayCreationInit.class" produce_same()

  "/class/parser/expr/arraycreationexpr/ArrayCreationNoInit.class" produce_same()

  "/class/parser/expr/assignexpr/AND.class" produce_same()

  "/class/parser/expr/assignexpr/DIVIDE.class" produce_same()

  "/class/parser/expr/assignexpr/LEFT_SHIFT.class" produce_same()

  "/class/parser/expr/assignexpr/MINUS.class" produce_same()

  "/class/parser/expr/assignexpr/MULTIPLY.class" produce_same()

  "/class/parser/expr/assignexpr/OR.class" produce_same()

  "/class/parser/expr/assignexpr/PLUS.class" produce_same()

  "/class/parser/expr/assignexpr/REMAINDER.class" produce_same()

  "/class/parser/expr/assignexpr/SIGNED_RIGHT_SHIFT.class" produce_same()

  "/class/parser/expr/assignexpr/UNSIGNED_RIGHT_SHIFT.class" produce_same()

  "/class/parser/expr/assignexpr/XOR.class" produce_same()

  "/class/parser/expr/binaryexpr/AND.class" produce_same()

  "/class/parser/expr/binaryexpr/BINARY_AND.class" produce_same()

  "/class/parser/expr/binaryexpr/BINARY_OR.class" produce_same()

  "/class/parser/expr/binaryexpr/DIVIDE.class" produce_same()

  "/class/parser/expr/binaryexpr/EQUALS.class" produce_same()

  "/class/parser/expr/binaryexpr/GREATER.class" produce_same()

  "/class/parser/expr/binaryexpr/GREATER_EQUALS.class" produce_same()

  "/class/parser/expr/binaryexpr/LEFT_SHIFT.class" produce_same()

  "/class/parser/expr/binaryexpr/LESS.class" produce_same()

  "/class/parser/expr/binaryexpr/LESS_EQUALS.class" produce_same()

  "/class/parser/expr/binaryexpr/MINUS.class" produce_same()

  "/class/parser/expr/binaryexpr/MULTIPLY.class" produce_same()

  "/class/parser/expr/binaryexpr/NOT_EQUALS.class" produce_same()

  "/class/parser/expr/binaryexpr/OR.class" produce_same()

  "/class/parser/expr/binaryexpr/PLUS.class" produce_same()

  "/class/parser/expr/binaryexpr/PLUS_multi.class" produce_same()

  "/class/parser/expr/binaryexpr/REMAINDER.class" produce_same()

  "/class/parser/expr/binaryexpr/SIGNED_RIGHT_SHIFT.class" produce_same()

  "/class/parser/expr/binaryexpr/UNSIGNED_RIGHT_SHIFT.class" produce_same()

  "/class/parser/expr/binaryexpr/XOR.class" produce_same()

  "/class/parser/expr/castexpr/CastObject.class" produce_same()

  "/class/parser/expr/classexpr/ClassExpression.class" produce_same()

  "/class/parser/expr/conditionalexpr/ConditionalExpr.class" produce_same()

  "/class/parser/expr/instanceofexpr/InstanceOfExpression.class" produce_same()

  "/class/parser/expr/methodcallexpr/MethodCall.class" produce_same()

  "/class/parser/expr/methodcallexpr/StaticCall.class" produce_same()

  "/class/parser/expr/objectcreationexpr/AnonymousClass.class" produce_same "/class/parser/expr/objectcreationexpr/AnonymousClass$1.class"

  "/class/parser/expr/objectcreationexpr/AnonymousClassMulti.class" produce_same("/class/parser/expr/objectcreationexpr/AnonymousClassMulti$1.class", "/class/parser/expr/objectcreationexpr/AnonymousClassMulti$2.class")

  "/class/parser/expr/objectcreationexpr/AnonymousClassScope.class" produce_same ("/class/parser/expr/objectcreationexpr/AnonymousClassScope$C.class", "/class/parser/expr/objectcreationexpr/AnonymousClassScope$1.class")

  "/class/parser/expr/unaryexpr/BITWISE_COMPLEMENT.class" produce_same()

  "/class/parser/expr/unaryexpr/Complex.class" produce_same()

  "/class/parser/expr/unaryexpr/LOGICAL_COMPLEMENT.class" produce_same()

  "/class/parser/expr/unaryexpr/MINUS.class" produce_same()

  "/class/parser/expr/unaryexpr/PLUS.class" produce_same()

  "/class/parser/expr/unaryexpr/POSTFIX_DECREMENT.class" produce_same()

  "/class/parser/expr/unaryexpr/POSTFIX_INCREMENT.class" produce_same()

  "/class/parser/expr/unaryexpr/PREFIX_DECREMENT.class" produce_same()

  "/class/parser/expr/unaryexpr/PREFIX_INCREMENT.class" produce_same()

  "/class/parser/expr/vardeclexpr/VariableDeclarationPrimitive.class" produce_same()

  "/class/parser/expr/vardeclexpr/VariableDeclarationPrimitive2.class" produce_same()

  "/class/parser/imports/ImportsTest.class" produce_same ("/class/parser/imports/pkg1/Ana.class", "/class/parser/imports/pkg2/Bob.class", "/class/parser/imports/pkg2/Cat.class")

  "/class/parser/imports/StaticImportsTest.class" produce_same ("/class/parser/imports/staticpkg/StaticContainer.class", "/class/parser/imports/staticpkg/StaticField.class")

  "/class/parser/stmt/assertstmt/Assert1.class" produce_same()

  "/class/parser/stmt/assertstmt/AssertObject.class" produce_same()

  "/class/parser/stmt/dostmt/DoWhile.class" produce_same()

  "/class/parser/stmt/dostmt/DoWhileNested.class" produce_same()

  "/class/parser/stmt/foreachstmt/Foreach.class" produce_same()

  "/class/parser/stmt/foreachstmt/ForeachNested.class" produce_same()

  "/class/parser/stmt/forstmt/For.class" produce_same()

  "/class/parser/stmt/forstmt/ForNested.class" produce_same()

  "/class/parser/stmt/forstmt/ForNoCompare.class" produce_same()

  "/class/parser/stmt/ifstmt/IfElseIf.class" produce_same()

  "/class/parser/stmt/labeledstmt/LabelBreak.class" produce_same()

  "/class/parser/stmt/labeledstmt/LabelContinue.class" produce_same()

  "/class/parser/stmt/localclassdeclarationstmt/LocalClass.class" produce_same "/class/parser/stmt/localclassdeclarationstmt/LocalClass$1Local.class"

  "/class/parser/stmt/localclassdeclarationstmt/LocalClassMulti.class" produce_same("/class/parser/stmt/localclassdeclarationstmt/LocalClassMulti$1Local.class", "/class/parser/stmt/localclassdeclarationstmt/LocalClassMulti$2Local.class", "/class/parser/stmt/localclassdeclarationstmt/LocalClassMulti$1Else.class")

  "/class/parser/stmt/switchstmt/Switch.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchNotMatch.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchString.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchStringNotMatch.class" produce_same()

  "/class/parser/stmt/synchronizedstmt/Synchronized.class" produce_same()

  "/class/parser/stmt/throwstmt/ThrowException.class" should "throw AssertionError" in {
    an[RuntimeException] should be thrownBy run("/class/parser/stmt/throwstmt/ThrowException.class", List())
  }

  "/class/parser/stmt/trystmt/TryCatch.class" produce_same()

  "/class/parser/stmt/trystmt/TryCatchFinally.class" produce_same()

  "/class/parser/stmt/trystmt/TryCatchFinallyWithResources.class" produce_same()

  "/class/parser/stmt/trystmt/TryCatchs.class" produce_same()

  "/class/parser/stmt/trystmt/TryCatchUnionType.class" produce_same()

  "/class/parser/stmt/trystmt/TryFinally.class" produce_same()

  "/class/parser/stmt/whilestmt/While.class" produce_same()

  "/class/parser/stmt/whilestmt/WhileNested.class" produce_same()

  "/class/parser/stringop/StringConcat.class" produce_same()

  "/class/parser/stringop/StringPlusEq.class" produce_same()

  "/class/parser/stringop/StringWithOther.class" produce_same()

  "/class/parser/comprehensive/DiskFileItem.class" no_exception()

  class TestFile(file: String) {
    def produce_same(other_files: String*): Unit = {
      file should "produce same result" in {
        val e = runBytecode(file, other_files)
        val r = run(file, other_files)
        assert(r == e)
      }
    }

    def no_exception(): Unit = {
      file should "successfully decoded" in {
        decode(file)
      }
    }
  }

  def loadClass(clz: JawaClass, classes: MMap[JawaType, Array[Byte]], ccl: CustomClassLoader, loadedClasses: MSet[JawaType]): Unit = {
    clz.getInterfaces.foreach { i =>
      loadClass(i, classes, ccl, loadedClasses)
    }
    if(clz.hasSuperClass) {
      loadClass(clz.getSuperClass, classes, ccl, loadedClasses)
    }
    classes.get(clz.getType) match {
      case Some(bytecodes) =>
        if(!loadedClasses.contains(clz.getType)) {
          ccl.loadClass(clz.getType.name, bytecodes)
          loadedClasses.add(clz.getType)
        }
      case None =>
    }
  }

  def runBytecode(mainFile: String, classFiles: Seq[String]): Any = {
    val ccl: CustomClassLoader = new CustomClassLoader()
    val className: String = mainFile.substring(7, mainFile.length - 6).replace("/", ".")
    (mainFile +: classFiles).foreach { file =>
      val cname = file.substring(7, file.length - 6).replace("/", ".")
      val bytecodes = new PlainFile(getClass.getResource(file).getPath).toByteArray
      ccl.loadClass(cname, bytecodes)
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

  def decode(file: String): Unit = {
    val classfile = new JavaClassFile(new PlainFile(getClass.getResource(file).getPath))
    val cu = DeBytecode.process(classfile)
    println(cu.toCode)
  }

  def run(mainFile: String, classFiles: Seq[String]): Any = {
    val className: String = mainFile.substring(7, mainFile.length - 6).replace("/", ".")
    val ccl: CustomClassLoader = new CustomClassLoader()
    val pw = new PrintWriter(System.out)
    (mainFile +: classFiles).foreach { file =>
      val classfile = new JavaClassFile(new PlainFile(getClass.getResource(file).getPath))
      val cu = DeBytecode.process(classfile)
      println(cu.toCode)
      val css = new JavaByteCodeGenerator("1.8").generate(None, cu)
      css.foreach{ case (typ, bytes) =>
        JavaByteCodeGenerator.outputByteCodes(pw, bytes)
        ccl.loadClass(typ.name, bytes)
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
