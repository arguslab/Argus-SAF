/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import java.io.{File, FileOutputStream, InputStream, OutputStream}
import java.util.zip.{ZipEntry, ZipFile}

import scala.collection.JavaConverters._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object ZipUtil {
  val BUFSIZE = 4096
  val buffer = new Array[Byte](BUFSIZE)

  def unZip(source: String, targetFolder: String): Boolean = {
    val zipFile = new ZipFile(source)

    unzipAllFile(zipFile.entries.asScala.toList, getZipEntryInputStream(zipFile), new File(targetFolder))
  }

  def getZipEntryInputStream(zipFile: ZipFile)(entry: ZipEntry): InputStream = zipFile.getInputStream(entry)

  def unzipAllFile(entryList: List[ZipEntry], inputGetter: ZipEntry => InputStream, targetFolder: File): Boolean = {

    entryList match {
      case entry :: entries =>

        if (entry.isDirectory)
          new File(targetFolder, entry.getName).mkdirs
        else
          saveFile(inputGetter(entry), new FileOutputStream(new File(targetFolder, entry.getName)))

        unzipAllFile(entries, inputGetter, targetFolder)
      case _ =>
        true
    }

  }

  def saveFile(fis: InputStream, fos: OutputStream): Unit = {
    writeToFile(bufferReader(fis), fos)
    fis.close()
    fos.close()
  }

  def bufferReader(fis: InputStream)(buffer: Array[Byte]): (Int, Array[Byte]) = (fis.read(buffer), buffer)

  def writeToFile(reader: Array[Byte] => (Int, Array[Byte]), fos: OutputStream): Boolean = {
    val (length, data) = reader(buffer)
    if (length >= 0) {
      fos.write(data, 0, length)
      writeToFile(reader, fos)
    } else
      true
  }
}
