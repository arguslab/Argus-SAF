/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

import org.argus.jawa.core.util.FileUtil

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object GetDexFromJar {
  def main(args: Array[String]): Unit = {
    val dir = args(0)
    val dirUri = FileUtil.toUri(dir)
    FileUtil.listFiles(dirUri, ".jar", recursive = true) foreach {
      jarUri =>
        ApkFileUtil.getDexFile(jarUri, dirUri, createFolder = false)
    }
  }
}
