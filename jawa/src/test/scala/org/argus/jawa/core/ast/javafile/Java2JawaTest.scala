/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.javafile

import java.lang.reflect.InvocationTargetException

import org.argus.jawa.core.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.core._
import org.argus.jawa.core.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class Java2JawaTest extends FlatSpec with Matchers {

  val DEBUG = true

  implicit def file(file: String): TestFile = {
    new TestFile(file)
  }

//  "/java/parser/cons/StaticInitializer.java" produce (1)
//
//  "/java/parser/cons/StaticInitializerMixed.java" produce (2)
//
//  "/java/parser/cons/StaticInitializerWithStaticBlock.java" produce (1)
//
//  "/java/parser/cons/ConstructorWithoutSuper.java" produce (1)
//
//  "/java/parser/cons/ConstructorWithSuper.java" produce (1)
//
//  "/java/parser/cons/InnerConstructor.java" produce (1)
//
//  "/java/parser/expr/arraycreationexpr/ArrayCreationComplex.java" produce (11)
//
//  "/java/parser/expr/arraycreationexpr/ArrayCreationInit.java" produce (3)
//
//  "/java/parser/expr/arraycreationexpr/ArrayCreationNoInit.java" produce (2)
//
//  "/java/parser/expr/assignexpr/AND.java" produce (0)
//
//  "/java/parser/expr/assignexpr/DIVIDE.java" produce (3)
//
//  "/java/parser/expr/assignexpr/LEFT_SHIFT.java" produce (4)
//
//  "/java/parser/expr/assignexpr/MINUS.java" produce (-1)
//
//  "/java/parser/expr/assignexpr/MULTIPLY.java" produce (6)
//
//  "/java/parser/expr/assignexpr/OR.java" produce (3)
//
//  "/java/parser/expr/assignexpr/PLUS.java" produce (3)
//
//  "/java/parser/expr/assignexpr/REMAINDER.java" produce (0)
//
//  "/java/parser/expr/assignexpr/SIGNED_RIGHT_SHIFT.java" produce (2)
//
//  "/java/parser/expr/assignexpr/UNSIGNED_RIGHT_SHIFT.java" produce (2)
//
//  "/java/parser/expr/assignexpr/XOR.java" produce (3)
//
//  "/java/parser/expr/binaryexpr/AND.java" produce (false)
//
//  "/java/parser/expr/binaryexpr/BINARY_AND.java" produce (0)
//
//  "/java/parser/expr/binaryexpr/BINARY_OR.java" produce (1)
//
//  "/java/parser/expr/binaryexpr/DIVIDE.java" produce (0)
//
//  "/java/parser/expr/binaryexpr/EQUALS.java" produce (false)
//
//  "/java/parser/expr/binaryexpr/GREATER.java" produce (false)
//
//  "/java/parser/expr/binaryexpr/GREATER_EQUALS.java" produce (true)
//
//  "/java/parser/expr/binaryexpr/LEFT_SHIFT.java" produce (2)
//
//  "/java/parser/expr/binaryexpr/LESS.java" produce (true)
//
//  "/java/parser/expr/binaryexpr/LESS_EQUALS.java" produce (true)
//
//  "/java/parser/expr/binaryexpr/MINUS.java" produce (0)
//
//  "/java/parser/expr/binaryexpr/MULTIPLY.java" produce (6)
//
//  "/java/parser/expr/binaryexpr/NOT_EQUALS.java" produce (true)
//
//  "/java/parser/expr/binaryexpr/OR.java" produce (true)
//
//  "/java/parser/expr/binaryexpr/PLUS.java" produce (3)
//
//  "/java/parser/expr/binaryexpr/PLUS_multi.java" produce (8)
//
//  "/java/parser/expr/binaryexpr/REMAINDER.java" produce (1)
//
//  "/java/parser/expr/binaryexpr/SIGNED_RIGHT_SHIFT.java" produce (1)
//
//  "/java/parser/expr/binaryexpr/UNSIGNED_RIGHT_SHIFT.java" produce (1)
//
//  "/java/parser/expr/binaryexpr/XOR.java" produce (true)
//
//  "/java/parser/expr/castexpr/CastObject.java" produce (1)
//
//  "/java/parser/expr/classexpr/ClassExpression.java" produce (true)
//
//  "/java/parser/expr/conditionalexpr/ConditionalExpr.java" produce (3)
//
//  "/java/parser/expr/instanceofexpr/InstanceOfExpression.java" produce (true)
//
//  "/java/parser/expr/methodcallexpr/MethodCall.java" produce (2)
//
//  "/java/parser/expr/methodcallexpr/StaticCall.java" produce (2)
//
//  "/java/parser/expr/objectcreationexpr/AnonymousClass.java" produce ("sr")
//
//  "/java/parser/expr/objectcreationexpr/AnonymousClassMulti.java" produce ("srdd")
//
////  "/java/parser/expr/objectcreationexpr/AnonymousClassScope.java" produce (2)
//
//  "/java/parser/expr/unaryexpr/BITWISE_COMPLEMENT.java" produce (-9)
//
//  "/java/parser/expr/unaryexpr/Complex.java" produce (-3)
//
//  "/java/parser/expr/unaryexpr/LOGICAL_COMPLEMENT.java" produce (false)
//
//  "/java/parser/expr/unaryexpr/MINUS.java" produce (-1)
//
//  "/java/parser/expr/unaryexpr/PLUS.java" produce (1)
//
//  "/java/parser/expr/unaryexpr/POSTFIX_DECREMENT.java" produce (1)
//
//  "/java/parser/expr/unaryexpr/POSTFIX_INCREMENT.java" produce (1)
//
//  "/java/parser/expr/unaryexpr/PREFIX_DECREMENT.java" produce (0)
//
//  "/java/parser/expr/unaryexpr/PREFIX_INCREMENT.java" produce (2)
//
//  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive.java" produce (3)
//
//  "/java/parser/expr/vardeclexpr/VariableDeclarationPrimitive2.java" produce (3D)
//
//  "/java/parser/imports/ImportsTest.java" produce (7, true)
//
//  "/java/parser/imports/StaticImportsTest.java" produce (6, true)
//
//  "/java/parser/stmt/assertstmt/Assert1.java" should "throw AssertionError" in {
//    an[AssertionError] should be thrownBy run("/java/parser/stmt/assertstmt/Assert1.java", loadpkg = false)
//  }
//
//  "/java/parser/stmt/assertstmt/AssertObject.java" should "throw AssertionError" in {
//    an[AssertionError] should be thrownBy run("/java/parser/stmt/assertstmt/AssertObject.java", loadpkg = false)
//  }
//
//  "/java/parser/stmt/dostmt/DoWhile.java" produce (10)
//
//  "/java/parser/stmt/dostmt/DoWhileNested.java" produce (1002)
//
//  "/java/parser/stmt/foreachstmt/Foreach.java" produce (10)
//
//  "/java/parser/stmt/foreachstmt/ForeachNested.java" produce (80)
//
//  "/java/parser/stmt/forstmt/For.java" produce (45)
//
//  "/java/parser/stmt/forstmt/ForNested.java" produce (50)
//
//  "/java/parser/stmt/forstmt/ForNoCompare.java" produce (10)
//
//  "/java/parser/stmt/ifstmt/IfElseIf.java" produce (11)
//
//  "/java/parser/stmt/labeledstmt/LabelBreak.java" produce (10)
//
//  "/java/parser/stmt/labeledstmt/LabelContinue.java" produce (11)
//
//  "/java/parser/stmt/localclassdeclarationstmt/LocalClass.java" produce (1)
//
//  "/java/parser/stmt/localclassdeclarationstmt/LocalClassMulti.java" produce (6)
//
//  "/java/parser/stmt/switchstmt/Switch.java" produce (1101)
//
//  "/java/parser/stmt/switchstmt/SwitchNotMatch.java" produce (1)
//
//  "/java/parser/stmt/switchstmt/SwitchString.java" produce (1101)
//
//  "/java/parser/stmt/switchstmt/SwitchStringNotMatch.java" produce (1)
//
////  "/java/parser/stmt/synchronizedstmt/Synchronized.java" produce (1)
//
//  "/java/parser/stmt/throwstmt/ThrowException.java" should "throw AssertionError" in {
//    an[RuntimeException] should be thrownBy run("/java/parser/stmt/throwstmt/ThrowException.java", loadpkg = false)
//  }
//
//  "/java/parser/stmt/trystmt/TryCatch.java" produce (1)
//
//  "/java/parser/stmt/trystmt/TryCatchFinally.java" produce (2)
//
//  "/java/parser/stmt/trystmt/TryCatchFinallyWithResources.java" produce (1010)
//
//  "/java/parser/stmt/trystmt/TryCatchs.java" produce (4)
//
//  "/java/parser/stmt/trystmt/TryCatchUnionType.java" produce (4)
//
//  "/java/parser/stmt/trystmt/TryFinally.java" produce (2)
//
//  "/java/parser/stmt/whilestmt/While.java" produce (10)
//
//  "/java/parser/stmt/whilestmt/WhileNested.java" produce (1002)
//
//  "/java/parser/stringop/StringConcat.java" produce ("abcc")
//
//  "/java/parser/stringop/StringPlusEq.java" produce ("abc")
//
//  "/java/parser/stringop/StringWithOther.java" produce ("aclass java.lang.Object1c")

  class TestFile(file: String) {
    def produce(tp: Any, loadpkg: Boolean = false): Unit = {
      file should "produce expected result" in {
        val r = run(file, loadpkg)
        assert(r == tp)
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

  def run(file: String, loadpkg: Boolean): Any = {
    val path = file.substring(0, file.lastIndexOf("/"))
    val className = file.substring(6, file.length - 5).replace("/", ".")
    val global = new Global("test", new PrintReporter(MsgLevel.INFO))
    global.setJavaLib(getClass.getResource("/libs/rt.jar").getPath)
    val map = if(loadpkg) {
      global.load(FileUtil.toUri(getClass.getResource(path).getPath), Constants.JAVA_FILE_EXT)
    } else {
      global.load(FileUtil.toUri(getClass.getResource(file).getPath))
    }
    val ccl: CustomClassLoader = new CustomClassLoader()
    val classes: MMap[JawaType, Array[Byte]] = mmapEmpty
    val sfs = map.map{case (_, sf) => sf}.toSet
    sfs.foreach { sf =>
      val jsf = sf.asInstanceOf[JavaSourceFile]
      val cu = jsf.getJawaCU
      println(cu.toCode)
      val css = new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
      classes ++= css
    }
    val loadedClasses: MSet[JawaType] = msetEmpty
    classes.foreach { case (typ, _) =>
      val clz = global.getClassOrResolve(typ)
      loadClass(clz, classes, ccl, loadedClasses)
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
