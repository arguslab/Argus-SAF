/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.util.cp

import java.io.File

import org.argus.jawa.compiler.compile.io.Using

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ClasspathUtilities {
  def isArchive(file: File): Boolean = isArchive(file, contentFallback = false)

  def isArchive(file: File, contentFallback: Boolean): Boolean =
    file.isFile && (isArchiveName(file.getName) || (contentFallback && hasZipContent(file)))

  def isArchiveName(fileName: String): Boolean = fileName.endsWith(".jar") || fileName.endsWith(".zip")
  
  def hasZipContent(file: File): Boolean = try {
    Using.fileInputStream(file) { in =>
      (in.read() == 0x50) &&
      (in.read() == 0x4b) &&
      (in.read() == 0x03) &&
      (in.read() == 0x04)
    }
  } catch { case e: Exception => false }
}
