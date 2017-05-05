/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import java.lang.reflect.InvocationTargetException

import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.dedex.`type`.GenerateTypedJawa
import org.argus.jawa.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.compiler.lexer.JawaLexer
import org.argus.jawa.compiler.parser.JawaParser
import org.argus.jawa.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core.{Global, JawaType, MsgLevel, NoLibraryAPISummary, NoReporter, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.{FlatSpec, Matchers}
import java.lang.reflect.Method

/**
  * Created by fgwei on 4/24/17.
  */
class LocalTypeResolverTest extends FlatSpec with Matchers {
  val DEBUG = true

  "Resolve local type" should "get same result on ArrayAccess1" in {
    assert(compareValue("/array/ArrayAccess1.jawa"))
  }

  "Resolve local type" should "get same result on ArrayAccess2" in {
    assert(compareValue("/array/ArrayAccess2.jawa"))
  }

  "Resolve local type" should "get same result on ArrayAccess3" in {
    assert(compareValue("/array/ArrayAccess3.jawa"))
  }

  "Resolve local type" should "get same result on ArrayCopy" in {
    assert(compareValue("/array/ArrayCopy.jawa"))
  }

  "Resolve local type" should "get same result on ArrayFill1" in {
    assert(compareClass("/array/ArrayFill1.jawa"))
  }

  "Resolve local type" should "get same result on ArrayFill2" in {
    assert(compareClass("/array/ArrayFill2.jawa"))
  }

  "Resolve local type" should "get same result on ArrayLength1" in {
    assert(compareValue("/array/ArrayLength1.jawa"))
  }

  "Resolve local type" should "get same result on Cmp1" in {
    assert(compareValue("/cmp/Cmp1.jawa"))
  }

  "Resolve local type" should "get same result on Cmp2" in {
    assert(compareValue("/cmp/Cmp2.jawa"))
  }

  "Resolve local type" should "get same result on ConstClass1" in {
    assert(compareClass("/constclass/ConstClass1.jawa"))
  }

  "Resolve local type" should "get same result on ConstClass2" in {
    assert(compareClass("/constclass/ConstClass2.jawa"))
  }

  "Resolve local type" should "get same result on DoubleLong1" in {
    assert(compareValue("/doublelong/DoubleLong1.jawa"))
  }

  "Resolve local type" should "get same result on Exceptions1" in {
    assert(compareValue("/exception/Exceptions1.jawa"))
  }

  "Resolve local type" should "get same result on Exceptions2" in {
    assert(compareValue("/exception/Exceptions2.jawa"))
  }

  "Resolve local type" should "get same result on Exceptions3" in {
    assert(compareValue("/exception/Exceptions3.jawa"))
  }

  "Resolve local type" should "throw an exception on Exceptions4" in {
    assert(compareException("/exception/Exceptions4.jawa"))
  }

  "Resolve local type" should "get same result on FieldAccess1" in {
    assert(compareValue("/field/FieldAccess1.jawa"))
  }

  "Resolve local type" should "get same result on FieldAccess2" in {
    assert(compareValue("/field/FieldAccess2.jawa"))
  }

  "Resolve local type" should "get same result on Instanceof1" in {
    assert(compareValue("/instance/Instanceof1.jawa"))
  }

  "Resolve local type" should "get same result on Instanceof2" in {
    assert(compareValue("/instance/Instanceof2.jawa"))
  }

  "Resolve local type" should "get same result on IfJump1" in {
    assert(compareValue("/jump/IfJump1.jawa"))
  }

  "Resolve local type" should "get same result on IfJump2" in {
    assert(compareValue("/jump/IfJump2.jawa"))
  }

  "Resolve local type" should "get same result on SwitchJump1" in {
    assert(compareValue("/jump/SwitchJump1.jawa"))
  }

  "Resolve local type" should "get same result on SwitchJump2" in {
    assert(compareValue("/jump/SwitchJump2.jawa"))
  }

  "Resolve local type" should "get same result on Monitor1" in {
    assert(compareValue("/monitor/Monitor1.jawa"))
  }

  private def compareValue(path: String): Boolean = {
    val (m, m2) = compare(path)
    m.invoke(null) == m2.invoke(null)
  }

  private def compareClass(path: String): Boolean = {
    val (m, m2) = compare(path)
    m.invoke(null).getClass == m2.invoke(null).getClass
  }

  private def compareException(path: String): Boolean = {
    val (m, m2) = compare(path)
    try {
      m.invoke(null)
      false
    } catch {
      case e: Exception =>
        try {
          m2.invoke(null)
          false
        } catch {
          case e2: Exception =>
            e.getClass == e2.getClass
        }
    }
  }

  private def compare(path: String): (Method, Method) = {
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
    val untyped = getClass.getResource("/jawa_untyped" + path).getPath
    val global = new Global("test", reporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(FileUtil.toUri(untyped), NoLibraryAPISummary.isLibraryClass)
    val newcode = GenerateTypedJawa(FileUtil.readFileContent(FileUtil.toUri(untyped)), global)
    val cu = new JawaParser(JawaLexer.tokenise(Left(newcode), reporter).toArray, reporter).compilationUnit(true)
    val css = new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
    val typed = getClass.getResource("/jawa_typed" + path).getPath
    val cu2 = new JawaParser(JawaLexer.tokenise(Left(FileUtil.readFileContent(FileUtil.toUri(typed))), reporter).toArray, reporter).compilationUnit(true)
    val css2 = new JavaByteCodeGenerator("1.8").generate(Some(global), cu2)
    val ccl: CustomClassLoader = new CustomClassLoader()
    val ccl2: CustomClassLoader = new CustomClassLoader()
    css foreach {
      case (typ, bytecodes) =>
        try{
          val bytecodes2 = css2(typ)
          val c = ccl.loadClass(typ.name, bytecodes)
          val m = c.getMethod("main")
          val c2 = ccl2.loadClass(typ.name, bytecodes2)
          val m2 = c2.getMethod("main")
          return (m, m2)
        } catch {
          case ite: InvocationTargetException =>
            throw ite.getTargetException
          case ilv: java.lang.VerifyError =>
            throw new RuntimeException(ilv.getMessage)
        }
    }
    throw new RuntimeException("Should not reach here.")
  }

  "Dedex data.dex" should "produce expected code" in {
    assert(resolve(getClass.getResource("/dexes/data.dex").getPath))
  }

  "Dedex comprehensive.dex" should "produce expected code" in {
    assert(resolve(getClass.getResource("/dexes/comprehensive.dex").getPath))
  }

  "Dedex comprehensive.odex" should "produce expected code" in {
    assert(resolve(getClass.getResource("/dexes/comprehensive.odex").getPath))
  }

//  "Dedex oat file BasicDreams.odex" should "produce expected code" in {
//    assert(resolve(getClass.getResource("/dexes/BasicDreams.odex").getPath))
//  }

  val recordFilter: (JawaType => Boolean) = { ot =>
    if(ot.name.startsWith("android.support.v4")){
      false
    } else if (ot.name.startsWith("android.support.v13")) {
      false
    } else if (ot.name.startsWith("android.support.v7")){
      false
    } else if (ot.name.startsWith("android.support.design")) {
      false
    } else if (ot.name.startsWith("android.support.annotation")) {
      false
    } else if(ot.name.endsWith(".BuildConfig") ||
      ot.name.endsWith(".Manifest") ||
      ot.name.contains(".Manifest$") ||
      ot.name.endsWith(".R") ||
      ot.name.contains(".R$")) {
      false
    } else true
  }

  private def resolve(filePath: String): Boolean = {
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
    val dedex = new JawaDeDex
    val dexUri = FileUtil.toUri(filePath)
    val settings = DecompilerSettings(debugMode = false, forceDelete = false, DecompileStrategy(DecompileLayout(""), NoLibraryAPISummary), new NoReporter)
    dedex.decompile(dexUri, settings)
    val global = new Global("test", reporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(dedex.getCodes, NoLibraryAPISummary.isLibraryClass)
    val total = dedex.getCodes.size
    var i = 0
    val newcodes = dedex.getCodes.map { case (t, code) =>
      i += 1
      println(s"$total:$i:$t")
      GenerateTypedJawa(code, global)
    }
    newcodes.foreach { code =>
      val cu = new JawaParser(JawaLexer.tokenise(Left(code), reporter).toArray, reporter).compilationUnit(true)
      new JavaByteCodeGenerator("1.8").generate(Some(global), cu)
    }
    true
  }
}
