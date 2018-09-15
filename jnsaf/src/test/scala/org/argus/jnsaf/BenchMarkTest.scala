package org.argus.jnsaf

import java.io.File

import org.argus.amandroid.core.decompile.ConverterUtil
import org.argus.jawa.core.JawaType
import org.argus.jawa.core.util.{FileUtil, IMap}
import org.argus.jawa.summary.store.TaintStore
import org.argus.jnsaf.analysis.TaintAnalysis
import org.scalatest.tagobjects.Slow
import org.scalatest.{FlatSpec, Matchers}

class BenchMarkTest extends FlatSpec with Matchers {
  final val DEBUG: Boolean = false

  "native_complexdata" should "have leak" taggedAs Slow in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_complexdata.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_complexdata.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_heap_modify" should "have leak" taggedAs Slow in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_heap_modify.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_heap_modify.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_leak" should "have leak" in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_leak.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_leak.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_noleak" should "have no leak" in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_noleak.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_noleak.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.isEmpty
        case None =>
          false
      })
  }

  "native_source" should "have leak" in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_source.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_source.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  "native_method_overloading" should "have leak" in {
    val res = taintAnalysis(getClass.getResource("/NativeFlowBench/native_method_overloading.apk").getPath)
    assert(
      res.get(new JawaType("org.arguslab.native_method_overloading.MainActivity")) match {
        case Some(store) =>
          store.getTaintedPaths.nonEmpty
        case None =>
          false
      })
  }

  def taintAnalysis(apkFile: String): IMap[JawaType, TaintStore] = {
    System.getProperties.setProperty("jpy.config", "jpy/jpyconfig.properties")
    val output = new File(apkFile).getParent + File.separator + "output"
    val res = TaintAnalysis(apkFile, output, debug = true, guessPackage = true)
    if(!DEBUG) {
      ConverterUtil.cleanDir(FileUtil.toUri(output))
    }
    res
  }
}
