/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core

import java.io.{File, FileInputStream, InputStream}

import org.ini4j.Wini
import org.argus.jawa.core.util.FileUtil

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class AmandroidSettings(amandroid_home: String, iniPathOpt: Option[String]) {
  private val amandroid_home_uri = FileUtil.toUri(amandroid_home)
  private def defaultLibFiles =
    amandroid_home + "/androidSdk/android-25/android.jar" + java.io.File.pathSeparator +
    amandroid_home + "/androidSdk/support/v4/android-support-v4.jar" + java.io.File.pathSeparator +
    amandroid_home + "/androidSdk/support/v13/android-support-v13.jar" + java.io.File.pathSeparator +
    amandroid_home + "/androidSdk/support/v7/android-support-v7-appcompat.jar"
  private def defaultThirdPartyLibFile = amandroid_home + "/liblist.txt"
  private val iniUri = {
    iniPathOpt match {
      case Some(path) => FileUtil.toUri(path)
      case None => FileUtil.appendFileName(amandroid_home_uri, "config.ini")
    }
  }
  private val ini = new Wini(FileUtil.toFile(iniUri))
  def timeout: Int = Option(ini.get("analysis", "timeout", classOf[Int])).getOrElse(5)
  def dependence_dir: Option[String] = Option(ini.get("general", "dependence_dir", classOf[String]))
  def debug: Boolean = ini.get("general", "debug", classOf[Boolean])
  def lib_files: String = Option(ini.get("general", "lib_files", classOf[String])).getOrElse(defaultLibFiles)
  def third_party_lib_file: String = Option(ini.get("general", "third_party_lib_file", classOf[String])).getOrElse(defaultThirdPartyLibFile)
  def actor_conf_file: InputStream = Option(ini.get("concurrent", "actor_conf_file", classOf[String])) match {
    case Some(path) => new FileInputStream(path)
    case None => getClass.getResourceAsStream("/application.conf")
  }
  def static_init: Boolean = ini.get("analysis", "static_init", classOf[Boolean])
  def parallel: Boolean = ini.get("analysis", "parallel", classOf[Boolean])
  def k_context: Int = ini.get("analysis", "k_context", classOf[Int])
  def sas_file: String = Option(ini.get("analysis", "sas_file", classOf[String])).getOrElse(amandroid_home + File.separator + "taintAnalysis" + File.separator + "sourceAndSinks" + File.separator + "TaintSourcesAndSinks.txt")
  def native_sas_file: String = Option(ini.get("analysis", "sas_file", classOf[String])).getOrElse(amandroid_home + File.separator + "taintAnalysis" + File.separator + "sourceAndSinks" + File.separator + "NativeSourcesAndSinks.txt")
  def injection_sas_file: String = Option(ini.get("analysis", "injection_sas_file", classOf[String])).getOrElse(amandroid_home + File.separator + "taintAnalysis" + File.separator + "sourceAndSinks" + File.separator + "IntentInjectionSourcesAndSinks.txt")
}
