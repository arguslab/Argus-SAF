/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
case class DecompilerSettings(apk: File,
                              dpsuri: Option[FileResourceUri],
                              dexLog: Boolean,
                              debugMode: Boolean,
                              removeSupportGen: Boolean,
                              forceDelete: Boolean,
                              listener: Option[PilarStyleCodeGeneratorListener] = None,
                              layout: DecompileLayout) {
  def apkUri: FileResourceUri = FileUtil.toUri(apk)
}

case class DecompileLayout(outputLocation: File,
                           createFolder: Boolean,
                           srcFolder: String,
                           createSeparateFolderForDexes: Boolean) {
  def outputUri: FileResourceUri = FileUtil.toUri(outputLocation)
}