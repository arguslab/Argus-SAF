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

import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.util.AndroidLibraryAPISummary
import org.argus.jawa.core.util.MyFileUtil
import org.argus.jawa.core.{Constants, Global, Reporter}
import org.sireum.util._

object GlobalUtil {
  def buildGlobal(fileUri: FileResourceUri, reporter: Reporter, outApkUri: FileResourceUri, srcs: ISet[String]): Global = {
    val global = new Global(fileUri, reporter)
    global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
    srcs foreach {
      src =>
        val fileUri = MyFileUtil.appendFileName(outApkUri, src)
        if(FileUtil.toFile(fileUri).exists()) {
          //store the app's pilar code in AmandroidCodeSource which is organized class by class.
          global.load(fileUri, Constants.PILAR_FILE_EXT, AndroidLibraryAPISummary)
        }
    }
    global
  }
}
