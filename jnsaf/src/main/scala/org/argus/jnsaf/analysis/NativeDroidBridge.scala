/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.analysis

import java.io.File

import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.jawa.core.{Reporter, Signature}
import org.argus.jawa.core.util._

/**
  * Created by fgwei on 4/26/17.
  */
class NativeDroidBridge(reporter: Reporter) {
  private val TITLE = "AngrBridge"
  private val DEBUG = true

//  val projects: MMap[String, PyObject] = mmapEmpty
//  var ssm: PyObject = _

  private val native_ss_file = AndroidGlobalConfig.amandroid_home + File.separator + "taintAnalysis" + File.separator + "sourceAndSinks" + File.separator + "NativeSourcesAndSinks.txt"
  private val java_ss_file = AndroidGlobalConfig.settings.sas_file

  def getSoFilePath(dirUri: FileResourceUri, soFileName: String, order: IList[String] = List("armeabi", "armeabi-v7a", "x86", "mips")): Option[String] = {
    val soFiles: IMap[String, String] = FileUtil.listFiles(dirUri, soFileName, recursive = true).map { soUri =>
      val f = FileUtil.toFile(soUri)
      (f.getParentFile.getName, f.getCanonicalPath)
    }.toMap
    val archOpt: Option[String] = order.find { arch =>
      soFiles.contains(arch)
    }
    archOpt.map { arch =>
      soFiles.getOrElse(arch, throw new RuntimeException("Should never be here."))
    }
  }

  def getAllSoFilePath(dirUri: FileResourceUri, order: IList[String] = List("armeabi", "armeabi-v7a", "x86", "mips")): IList[String] = {
    val soFiles = FileUtil.listFiles(dirUri, ".so", recursive = true)
    val res: MList[String] = mlistEmpty
    order.foreach { arch =>
      soFiles.foreach { soUri =>
        val f = FileUtil.toFile(soUri)
        if(f.getParentFile.getName == arch) {
          res += f.getCanonicalPath
        }
      }
    }
    res.toList
  }

  def genSummary(soFile: String, methodName: String, sig: Signature, parameters: String): (String, String) = {
    try {
//      val mainModule = PyModule.importModule("nativedroid")
//      var obj: PyObject = null
//      TimeUtil.timed("NativeDroid gen_summary", reporter) {
//        obj = mainModule.call("gen_summary", soFile, methodName, sig.signature, parameters, native_ss_file, java_ss_file)
//      }
//      val v = obj.getObjectArrayValue(classOf[String])
//      reporter.echo("Analyzed instructions", v(2))
//      (v(0), v(1).trim)
      ("", s"`${sig.signature}`:;")
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        if (DEBUG)
          e.printStackTrace()
        ("", s"`${sig.signature}`:;")
    }
  }

  def hasNativeActivity(soFile: String, customEntry: Option[String]): Boolean = {
    customEntry match {
      case Some(entry) => hasSymbol(soFile, entry)
      case None =>
        if(hasSymbol(soFile, "android_main")) {
          true
        } else {
          hasSymbol(soFile, "ANativeActivity_onCreate")
        }
    }
  }

  def hasSymbol(soFile: String, symbol: String): Boolean = {
    try {
//      val mainModule = PyModule.importModule("nativedroid")
//      val obj: PyObject = mainModule.call("has_symbol", soFile, symbol)
//      obj.getIntValue == 1
      true
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        if (DEBUG)
          e.printStackTrace()
        false
    }
  }

  def analyseNativeActivity(soFile: String, customEntry: Option[String]): String = {
    try {
//      val mainModule = PyModule.importModule("nativedroid")
//      var obj: PyObject = null
//      TimeUtil.timed("NativeDroid native_activity_analysis", reporter) {
//        obj = mainModule.call("native_activity_analysis", soFile, customEntry.getOrElse(""), native_ss_file, java_ss_file)
//      }
//      val v = obj.getStringValue
//      reporter.echo("Analyzed instructions", v)
//      v
      "1"
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        if (DEBUG)
          e.printStackTrace()
        "-1"
    }
  }

  def loadBinary(soFile: String): Boolean = {
    try {
//      val mainModule = PyModule.importModule("native_basic")
//      projects(new File(soFile).getName) = mainModule.call("register", soFile)
      true
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        if (DEBUG)
          e.printStackTrace()
        false
    }
  }

  def loadSSM(sasFile: String): Boolean = {
    try {
//      val mainModule = PyModule.importModule("analyses")
//      ssm = mainModule.call("generate_ssm", sasFile)
      true
    } catch {
      case e: Throwable =>
        reporter.error(TITLE, e.getMessage)
        if (DEBUG)
          e.printStackTrace()
        false
    }
  }
}
