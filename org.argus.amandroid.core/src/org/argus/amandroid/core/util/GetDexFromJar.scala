/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

import org.sireum.util.FileUtil

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
