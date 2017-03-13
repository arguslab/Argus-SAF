/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.decompile

import java.io.File

import org.argus.amandroid.core.dedex.PilarStyleCodeGeneratorListener
import org.sireum.util._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
case class DecompilerSettings(dpsuri: Option[FileResourceUri],
                              dexLog: Boolean,
                              debugMode: Boolean,
                              removeSupportGen: Boolean,
                              forceDelete: Boolean,
                              listener: Option[PilarStyleCodeGeneratorListener] = None,
                              layout: DecompileLayout)

case class DecompileLayout(outputUri: FileResourceUri,
                           createFolder: Boolean = true,
                           srcFolder: String = "src",
                           createSeparateFolderForDexes: Boolean = true) {
  def outputFolder: File = FileUtil.toFile(outputUri)
  def sourceFolder(dexUri: FileResourceUri): String = {
    srcFolder + {
      if (createSeparateFolderForDexes) File.separator + {
        if (dexUri.startsWith(outputSrcUri)) dexUri.replace(outputSrcUri, "").replace(".dex", "").replace(".odex", "")
        else dexUri.substring(dexUri.lastIndexOf("/") + 1, dexUri.lastIndexOf("."))
      }.replaceAll("/", "_")
      else ""
    }
  }
  var outputSrcUri: FileResourceUri = outputUri
}