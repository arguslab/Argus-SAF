/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.classfile

import java.lang.reflect.InvocationTargetException

import org.argus.jawa.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core._
import org.argus.jawa.core.frontend.classfile.JavaClassFile
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

//  "/class/parser/cons/InnerConstructor.class" produce (1)

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

//  "/class/parser/expr/objectcreationexpr/AnonymousClass.class" produce_same()
//
//  "/class/parser/expr/objectcreationexpr/AnonymousClassMulti.class" produce_same()
//
  //  "/class/parser/expr/objectcreationexpr/AnonymousClassScope.class" produce (2)

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

//  "/class/parser/imports/ImportsTest.class" produce (7, true)
//
//  "/class/parser/imports/StaticImportsTest.class" produce (6, true)
//
//  "/class/parser/stmt/assertstmt/Assert1.class" should "throw AssertionError" in {
//    an[AssertionError] should be thrownBy run("/class/parser/stmt/assertstmt/Assert1.class", loadpkg = false)
//  }
//
//  "/class/parser/stmt/assertstmt/AssertObject.class" should "throw AssertionError" in {
//    an[AssertionError] should be thrownBy run("/class/parser/stmt/assertstmt/AssertObject.class", loadpkg = false)
//  }

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

  "/class/parser/stmt/localclassdeclarationstmt/LocalClass.class" produce_same()

  "/class/parser/stmt/localclassdeclarationstmt/LocalClassMulti.class" produce_same()

  "/class/parser/stmt/switchstmt/Switch.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchNotMatch.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchString.class" produce_same()

  "/class/parser/stmt/switchstmt/SwitchStringNotMatch.class" produce_same()

  "/class/parser/stmt/synchronizedstmt/Synchronized.class" produce_same()

//  "/class/parser/stmt/throwstmt/ThrowException.class" should "throw AssertionError" in {
//    an[RuntimeException] should be thrownBy run("/class/parser/stmt/throwstmt/ThrowException.class", loadpkg = false)
//  }

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

  class TestFile(file: String) {
    def produce_same(): Unit = {
      file should "produce same result" in {
        val e = runBytecode(List(file))
        val r = run(List(file))
        assert(e == r)
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

  def runBytecode(classFiles: Seq[String]): Any = {
    val ccl: CustomClassLoader = new CustomClassLoader()
    var className: String = ""
    classFiles.foreach { file =>
      className = file.substring(7, file.length - 6).replace("/", ".")
      val bytecodes = new PlainFile(getClass.getResource(file).getPath).toByteArray
      ccl.loadClass(className, bytecodes)
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

  def run(classFiles: Seq[String]): Any = {
    var className: String = ""
    val ccl: CustomClassLoader = new CustomClassLoader()
    classFiles.foreach { file =>
      className = file.substring(7, file.length - 6).replace("/", ".")
      val classfile = new JavaClassFile(new PlainFile(getClass.getResource(file).getPath))
      val cu = DeBytecode.process(classfile)
      println(cu.toCode)
      val css = new JavaByteCodeGenerator("1.8").generate(None, cu)
      css.foreach{ case (typ, bytes) =>
        ccl.loadClass(typ.name, bytes)
      }
      className = classfile.getType.name
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
