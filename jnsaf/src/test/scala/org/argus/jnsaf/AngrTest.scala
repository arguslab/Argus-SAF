/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf

import java.io.File

import org.argus.amandroid.core.decompile._
import org.argus.jawa.core.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util.FileUtil
import org.jpy.{PyLib, PyModule}
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 3/16/17.
  */
class AngrTest extends FlatSpec with Matchers {

  "icc_javatonative" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/icc_javatonative.apk").getPath)
    assert(res.endsWith(".so"))
  }

  "icc_nativetojava" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/icc_nativetojava.apk").getPath)
    assert(res.endsWith(".so"))
  }

  "native_complexdata" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/native_complexdata.apk").getPath)
    assert(res.endsWith(".so"))
  }

  "native_leak" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/native_leak.apk").getPath)
    assert(res.endsWith(".so"))
  }

  "native_noleak" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/native_noleak.apk").getPath)
    assert(res.endsWith(".so"))
  }

  "native_pure" should "success load binary" in {
    val res = loadBinary(getClass.getResource("/NativeFlowBench/native_pure.apk").getPath)
    assert(res.endsWith(".so"))
  }

  private def loadBinary(apkFile: String): String = {
    System.getProperties.setProperty("jpy.config", "jpy/jpyconfig.properties")
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.appendFileName(FileUtil.toUri(FileUtil.toFile(apkUri).getParent), "output")


    val importPath = new File("src/test/python").getCanonicalPath
    PyLib.startPython(importPath)
    val pyModule = PyModule.importModule("AngrWrapper")

    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, new PrintReporter(MsgLevel.INFO))
    var r1: String = ""
    try {
      ApkDecompiler.decompile(apkUri, settings)
      val soFile = FileUtil.toFilePath(FileUtil.listFiles(settings.strategy.layout.outputSrcUri, ".so", recursive = true).find(_.contains("x86")).get)
      r1 = pyModule.call("loadBinary", soFile).getStringValue
    } catch {
      case e: Throwable =>
        e.printStackTrace()
    } finally {
//      PyLib.stopPython()
      ConverterUtil.cleanDir(outputUri)
    }
    r1
  }
}
