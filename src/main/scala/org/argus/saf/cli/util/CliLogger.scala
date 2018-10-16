/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli.util

import java.io.{File, FileWriter, PrintWriter}
import java.text.SimpleDateFormat
import java.util.Date

/**
 * @author <a href="mailto:fgwei@k-state.edu">Fengguo Wei</a>
 */ 
object CliLogger {
  
  def timeStamp: String = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date)
  
  def outPrint(s : String) {
    scala.Console.out.print(s)
    scala.Console.out.flush()
  }

  def outPrintln(s : String) {
    scala.Console.out.println(s)
    scala.Console.out.flush()
  }

  def outPrintln() {
    scala.Console.out.println()
    scala.Console.out.flush()
  }

  def errPrintln(s : String) {
    scala.Console.err.println(s)
    scala.Console.err.flush()
  }

  def errPrintln() {
    scala.Console.err.println()
    scala.Console.err.flush()
  }
  
  def logError(dir: File, text: String, e: Throwable) {
    outPrintln()
    errPrintln(text + e.getMessage)
    val f = new File(dir, ".errorlog")
    f.getParentFile.mkdirs
    val fw = new FileWriter(f)
    try {
      val pw = new PrintWriter(fw)
      pw.println("An error occurred on " + timeStamp)
      e.printStackTrace(pw)
      fw.close()
      outPrintln("Written: " + f.getAbsolutePath)
    } catch {
      case e : Throwable =>
        errPrintln("Error: " + e.getMessage)
    }
  }
}
