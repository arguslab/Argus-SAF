/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import java.lang.reflect.InvocationTargetException

import org.argus.amandroid.core.decompile._
import org.argus.amandroid.core.dedex.`type`.GenerateTypedJawa
import org.argus.jawa.core.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.core.compiler.lexer.JawaLexer
import org.argus.jawa.core.compiler.parser.JawaParser
import org.argus.jawa.core.{Global, NoLibraryAPISummary}
import org.argus.jawa.core.util.FileUtil
import org.scalatest.{FlatSpec, Matchers}
import java.lang.reflect.Method

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.jawa.core.compiler.compile.JawaCompiler
import org.argus.jawa.core.compiler.util.ReadClassFile.CustomClassLoader
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{MsgLevel, NoReporter, PrintReporter}

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

  "Resolve local type" should "get same result on InstanceOf1" in {
    assert(compareValue("/instance/InstanceOf1.jawa"))
  }

  "Resolve local type" should "get same result on InstanceOf2" in {
    assert(compareValue("/instance/InstanceOf2.jawa"))
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
    global.load(FileUtil.toUri(untyped))
    val newcode = GenerateTypedJawa(FileUtil.readFileContent(FileUtil.toUri(untyped)), global)
    println(newcode)
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

  val recordFilter: JawaType => Boolean = { ot =>
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
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, DecompileStrategy(DecompileLayout(""), NoLibraryAPISummary), new NoReporter)
    dedex.decompile(dexUri, settings)
    val global = new Global("test", reporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.loadJawaCode(dedex.getCodes)
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

//  "ICC_Explicit_NoSrc_NoSink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_nosink.apk").getPath))
//  }
//
//  "ICC_Explicit_NoSrc_Sink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_explicit_nosrc_sink.apk").getPath))
//  }
//
//  "ICC_Explicit_Src_NoSink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_nosink.apk").getPath))
//  }
//
//  "ICC_Explicit_Src_Sink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath))
//  }
//
//  "ICC_Implicit_NoSrc_NoSink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_nosink.apk").getPath))
//  }
//
//  "ICC_Implicit_NoSrc_Sink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_implicit_nosrc_sink.apk").getPath))
//  }
//
//  "ICC_Implicit_Src_NoSink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_nosink.apk").getPath))
//  }
//
//  "ICC_Implicit_Src_Sink" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_implicit_src_sink.apk").getPath))
//  }
//
//  "ICC_IntentService" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_intentservice.apk").getPath))
//  }
//
//  "ICC_Stateful" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccHandling/icc_stateful.apk").getPath))
//  }
//
//  "ICC_DynRegister1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister1.apk").getPath))
//  }
//
//  "ICC_DynRegister2" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_dynregister2.apk").getPath))
//  }
//
//  "ICC_Explicit1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_explicit1.apk").getPath))
//  }
//
//  "ICC_Implicit1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_action.apk").getPath))
//  }
//
//  "ICC_Implicit2" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_category.apk").getPath))
//  }
//
//  "ICC_Implicit3" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data1.apk").getPath))
//  }
//
//  "ICC_Implicit4" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_data2.apk").getPath))
//  }
//
//  "ICC_Implicit5" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix1.apk").getPath))
//  }
//
//  "ICC_Implicit6" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/IccTargetFinding/icc_implicit_mix2.apk").getPath))
//  }
//
//  "ICC_RPC_Comprehensive" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/Mixed/icc_rpc_comprehensive.apk").getPath))
//  }
//
//  "RPC_LocalService" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/RpcHandling/rpc_localservice.apk").getPath))
//  }
//
//  "RPC_MessengerService" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/RpcHandling/rpc_messengerservice.apk").getPath))
//  }
//
//  "RPC_RemoteService" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/RpcHandling/rpc_remoteservice.apk").getPath))
//  }
//
//  "RPC_ReturnSensitive" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/icc-bench/RpcHandling/rpc_returnsensitive.apk").getPath))
//  }
//
//  "ActivityCommunication1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication1.apk").getPath))
//  }
//
//  "ActivityCommunication2" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication2.apk").getPath))
//  }
//
//  "ActivityCommunication3" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication3.apk").getPath))
//  }
//
//  "ActivityCommunication4" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication4.apk").getPath))
//  }
//
//  "ActivityCommunication5" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication5.apk").getPath))
//  }
//
//  "ActivityCommunication6" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication6.apk").getPath))
//  }
//
//  "ActivityCommunication7" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication7.apk").getPath))
//  }
//
//  "ActivityCommunication8" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ActivityCommunication8.apk").getPath))
//  }
//
//  "BroadcastTaintAndLeak1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/BroadcastTaintAndLeak1.apk").getPath))
//  }
//
//  "ComponentNotInManifest1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ComponentNotInManifest1.apk").getPath))
//  }
//
//  "EventOrdering1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/EventOrdering1.apk").getPath))
//  }
//
//  "IntentSink1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink1.apk").getPath))
//  }
//
//  "IntentSink2" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSink2.apk").getPath))
//  }
//
//  "IntentSource1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/IntentSource1.apk").getPath))
//  }
//
//  "ServiceCommunication1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/ServiceCommunication1.apk").getPath))
//  }
//
//  "SharedPreferences1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/SharedPreferences1.apk").getPath))
//  }
//
//  "Singletons1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/Singletons1.apk").getPath))
//  }
//
//  "UnresolvableIntent1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/InterComponentCommunication/UnresolvableIntent1.apk").getPath))
//  }
//
//  "AsyncTask1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/Threading/AsyncTask1.apk").getPath))
//  }
//
//  "Executor1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/Threading/Executor1.apk").getPath))
//  }
//
//  "JavaThread1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/Threading/JavaThread1.apk").getPath))
//  }
//
//  "JavaThread2" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/Threading/JavaThread2.apk").getPath))
//  }
//
//  "Looper1" should "successfully resolved" in {
//    assert(resolveApk(getClass.getResource("/droid-bench/Threading/Looper1.apk").getPath))
//  }

  private def resolveApk(filePath: String): Boolean = {
    val fileUri = FileUtil.toUri(filePath)
    val outputUri = FileUtil.toUri(filePath.substring(0, filePath.length - 4) + "_type")
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new PrintReporter(MsgLevel.NO)
    val strategy = DecompileStrategy(DecompileLayout(outputUri), NoLibraryAPISummary, sourceLevel = DecompileLevel.TYPED)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, new NoReporter)
    val yard = new ApkYard(reporter)
    val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
    val compiler = new JawaCompiler("1.8")
    val srcFiles = apk.getApplicationClassCodes.map{ case (_, sf) => sf.file.file}
    compiler.compile(srcFiles.toArray, Set().toArray, None, settings.progressBar)
    ConverterUtil.cleanDir(outputUri)
    true
  }
}
