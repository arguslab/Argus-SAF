/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.concurrent.util

import java.io.FileWriter

import org.argus.jawa.core.util.MyFileUtil
import org.sireum.util.{FileResourceUri, FileUtil}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class Recorder(outUri: FileResourceUri) {
  def decompile(apkName: String, succ: Boolean): Unit = {
    val rp = FileUtil.toFile(MyFileUtil.appendFileName(outUri, "decompile_report.txt"))
    this.synchronized {
      val writer = new FileWriter(rp, true)
      try {
        writer.write(apkName + " " + {if(succ) "success" else "failure"} + "\n")
      } catch {
        case e: Exception =>
          throw e
      } finally {
        writer.close()
      }
    }
  }

  def infocollect(apkName: String, succ: Boolean): Unit = {
    val rp = FileUtil.toFile(MyFileUtil.appendFileName(outUri, "info_collect_report.txt"))
    this.synchronized {
      val writer = new FileWriter(rp, true)
      try {
        writer.write(apkName + " " + {if(succ) "success" else "failure"} + "\n")
      } catch {
        case e: Exception =>
          throw e
      } finally {
        writer.close()
      }
    }
  }

  def pta(apkName: String, time: Long, succ: Boolean): Unit = {
    val rp = FileUtil.toFile(MyFileUtil.appendFileName(outUri, "pta_report.txt"))
    this.synchronized {
      val writer = new FileWriter(rp, true)
      try {
        writer.write(apkName + " " + time + "s " + {if(succ) "success" else "failure"} + "\n")
      } catch {
        case e: Exception =>
          throw e
      } finally {
        writer.close()
      }
    }
  }
}
