package org.argus.jnsaf.taint

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{MsgLevel, NoReporter, PrintReporter}
import org.argus.jawa.core.util.{FileUtil, IMap}
import org.argus.jawa.flow.summary.store.TaintStore
import org.argus.jnsaf.analysis.NativeMethodHandler
import org.argus.jnsaf.client.NativeDroidClient
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 1/28/18.
  */
class JNTaintAnalysisTest extends FlatSpec with Matchers {
  private final val DEBUG = false

//  "icc_javatonative" should "have 2 components" in {
//    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_javatonative.apk").getPath)
//    assert(res != null && res.model.getComponentInfos.size == 2)
//  }
//
//  "icc_nativetojava" should "have 2 components" in {
//    val res = loadApk(getClass.getResource("/NativeFlowBench/icc_nativetojava.apk").getPath)
//    assert(res != null && res.model.getComponentInfos.size == 2)
//  }
//
  "native_complexdata" should "have leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_complexdata.apk").getPath,
      getClass.getResource("/expected/native_complexdata/native_complexdata.safsu").getPath,
      getClass.getResource("/expected/native_complexdata/native_complexdata.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_complexdata.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_heap_modify" should "have leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_heap_modify.apk").getPath,
      getClass.getResource("/expected/native_heap_modify/native_heap_modify.safsu").getPath,
      getClass.getResource("/expected/native_heap_modify/native_heap_modify.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_heap_modify.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_leak" should "have leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_leak.apk").getPath,
      getClass.getResource("/expected/native_leak/native_leak.safsu").getPath,
      getClass.getResource("/expected/native_leak/native_leak.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_leak.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_noleak" should "have no leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_noleak.apk").getPath,
      getClass.getResource("/expected/native_noleak/native_noleak.safsu").getPath,
      getClass.getResource("/expected/native_noleak/native_noleak.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_noleak.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.isEmpty
        case None =>
          false
      })
  }
//
//  "native_pure" should "have 1 component" in {
//    val res = loadApk(getClass.getResource("/NativeFlowBench/native_pure.apk").getPath)
//    assert(res != null && res.model.getComponentInfos.size == 1)
//  }

  "native_source" should "have leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_source.apk").getPath,
      getClass.getResource("/expected/native_source/native_source.safsu").getPath,
      getClass.getResource("/expected/native_source/native_source.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_source.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_method_overloading" should "have leak" in {
    val res = analyze(
      getClass.getResource("/NativeFlowBench/native_method_overloading.apk").getPath,
      getClass.getResource("/expected/native_method_overloading/native_method_overloading.safsu").getPath,
      getClass.getResource("/expected/native_method_overloading/native_method_overloading.txt").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_method_overloading.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  private def analyze(apkFile: String, safsuFile: String, sasFile: String): IMap[JawaType, TaintStore] = {
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.appendFileName(FileUtil.toUri(FileUtil.toFile(apkUri).getParent), "output")
    val reporter = if(DEBUG) new PrintReporter(MsgLevel.INFO) else new NoReporter
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
    val handler = new NativeMethodHandler(new NativeDroidClient("localhost", 50051, reporter))
    val jntaint = new JNTaintAnalysis(apk, handler, reporter)
    val safsuFileUri = FileUtil.toUri(safsuFile)
    val name = FileUtil.filename(safsuFileUri)
    jntaint.provider.sm.registerExternalFile(safsuFileUri, name, fileAndSubsigMatch = false)
    jntaint.ssm.parseFile(sasFile)
    val res = jntaint.process
    ConverterUtil.cleanDir(outputUri)
    res
  }
}
