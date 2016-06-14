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

import java.io._

import org.sireum.util._
import java.net.URI

import org.argus.amandroid.core.dedex.{PilarDeDex, PilarStyleCodeGeneratorListener}
import org.argus.amandroid.core.util.FixResources
import org.argus.jawa.core.JawaType
import org.xml.sax.SAXParseException

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object Dex2PilarConverter {
  def convert(
      f: FileResourceUri, 
      targetDirUri: FileResourceUri, 
      out: FileResourceUri, 
      dpsuri: Option[FileResourceUri], 
      recordFilter: (JawaType => Boolean), 
      dexLog: Boolean, 
      debugMode: Boolean, 
      forceDelete: Boolean,
      listener: Option[PilarStyleCodeGeneratorListener] = None): FileResourceUri = {
    if(!forceDelete && FileUtil.toFile(targetDirUri).exists()) return targetDirUri
    ConverterUtil.cleanDir(targetDirUri)
    try {
      val pdd = new PilarDeDex
      pdd.decompile(f, Some(targetDirUri), dpsuri, recordFilter, dexLog, debugMode, listener)
      FixResources.fix(out, pdd)
    } catch {
      case spe: SAXParseException =>
      case ie: InterruptedException => throw ie
      case ex: Exception =>
        System.err.println("Given file is not a decompilable file: " + f)
    }
    targetDirUri
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ConverterUtil {

  def copy(srcUri: FileResourceUri, destUri: FileResourceUri) {
      def copyFile(f: File) {
        try {
          val fin = new FileInputStream(f)
          val dest = new File(new File(new URI(destUri)), f.getName)
          val fout = new FileOutputStream(dest)
          val buffer = new Array[Byte](1024)
          var bytesRead = fin.read(buffer)
          while (bytesRead > 0) {
            fout.write(buffer, 0, bytesRead)
            bytesRead = fin.read(buffer)
          }
          fin.close()
          fout.close()
        } catch {
          case e: Exception =>
            e.printStackTrace()
        }
      }

    val src = new File(new URI(srcUri))
//    val dest = new File(new URI(destUri))

    if (src.exists() && src.isDirectory) {
      src.listFiles().foreach { f =>
        if (f.isFile) {
          copyFile(f)
        }
      }
    }
  }

  def cleanDir(dirUri: FileResourceUri) {
    val dir = new File(new URI(dirUri))
    if (dir.exists)
      dir.listFiles.foreach { f =>
        if (f.isDirectory) {
          cleanDir(f.getAbsoluteFile.toURI.toASCIIString)
        }
        f.delete()
      }
  }
}
