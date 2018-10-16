/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import java.io.{BufferedReader, InputStreamReader}
import java.net.URLClassLoader
import java.text.NumberFormat

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object JVMUtil {
	def startSecondJVM[C](clazz: Class[C], jvmArgs: List[String], args: List[String], redirectStream: Boolean): Int = {
    val separator = System.getProperty("file.separator")
    val classpath = Thread.currentThread().getContextClassLoader.asInstanceOf[URLClassLoader].getURLs.map(_.getPath()).reduce((c1, c2) => c1 + java.io.File.pathSeparator + c2)
    val path = System.getProperty("java.home") + separator + "bin" + separator + "java"
    val commands: IList[String] = List(path) ::: jvmArgs ::: List("-cp", classpath, clazz.getCanonicalName.stripSuffix("$")) ::: args
    import scala.collection.JavaConverters._
    val processBuilder = new ProcessBuilder(commands.asJava)
    processBuilder.redirectErrorStream(redirectStream)
    val process = processBuilder.start()
    val is = process.getInputStream
    val isr = new InputStreamReader(is)
    val br = new BufferedReader(isr)
    var line = br.readLine()
    while (line != null) {
      println(line)
      line = br.readLine()
    }
    process.waitFor()
  }
  
  def showMemoryUsage(): Unit = {
    val runtime = Runtime.getRuntime
    val format = NumberFormat.getInstance()
    
    val sb = new StringBuilder()
    val maxMemory = runtime.maxMemory()
    val allocatedMemory = runtime.totalMemory()
    val freeMemory = runtime.freeMemory()
    
    sb.append("free memory: " + format.format(freeMemory / 1024 / 1024) + " ")
    sb.append("allocated memory: " + format.format(allocatedMemory / 1024 / 1024) + " ")
    sb.append("max memory: " + format.format(maxMemory / 1024 / 1024) + " ")
    sb.append("total free memory: " + format.format((freeMemory + (maxMemory - allocatedMemory)) / 1024 / 1024) + " ")
    println(sb.toString())
  }
}
