/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.decompile

import java.io._

import org.argus.jawa.core.util._
import java.net.URI
import java.util.concurrent.TimeoutException

import org.argus.amandroid.core.dedex.JawaDeDex
import org.argus.amandroid.core.util.FixResources
import org.xml.sax.SAXParseException

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object Dex2JawaConverter {
  def convert(dexUri: FileResourceUri, settings: DecompilerSettings): Unit = {
    val srcUri = settings.strategy.layout.sourceOutUri(dexUri)
    val libUri = settings.strategy.layout.libOutUri(dexUri)
    if(!settings.forceDelete && FileUtil.toFile(srcUri).exists()) return
    ConverterUtil.cleanDir(srcUri)
    ConverterUtil.cleanDir(libUri)
    try {
      val pdd = new JawaDeDex
      pdd.decompile(dexUri, settings)
      pdd.getCodes.foreach { case (typ, code) =>
        settings.strategy.outputCode(typ, code, dexUri)
      }
      settings.strategy.outputThirdPartyLibs()
      FixResources.fix(settings.strategy.layout.outputSrcUri, pdd)
    } catch {
      case _: SAXParseException =>
      case te: TimeoutException =>
        throw te
      case _: Exception =>
        System.err.println("Given file is not decompilable: " + dexUri)
    }
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
