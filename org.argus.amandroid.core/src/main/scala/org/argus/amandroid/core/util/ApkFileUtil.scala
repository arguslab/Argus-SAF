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

import org.sireum.util.FileResourceUri
import org.sireum.util.FileUtil
import org.sireum.util.ISeq
import java.io.IOException
import java.io.DataInputStream
import java.io.BufferedInputStream
import java.io.FileInputStream
import java.util.zip.ZipInputStream
import java.io.FileOutputStream

import org.argus.amandroid.core.Apk
import org.argus.jawa.core.util.MyFileUtil

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ApkFileUtil {
  def getDecompileableFiles(dirUri: FileResourceUri, recursive: Boolean = true): ISeq[FileResourceUri] = {
    FileUtil.listFiles(dirUri, "", recursive).filter(Apk.isDecompilable)
  }
  def getApks(dirUri: FileResourceUri, recursive: Boolean = true): ISeq[FileResourceUri] = {
    FileUtil.listFiles(dirUri, "", recursive).filter(Apk.isValidApk)
  }
  def getOutputUri(apkUri: FileResourceUri, outputUri: FileResourceUri): FileResourceUri = {
    val apkFile = FileUtil.toFile(apkUri)
    val dirName = try{apkFile.getName.substring(0, apkFile.getName.lastIndexOf("."))} catch {case e: IndexOutOfBoundsException => apkFile.getName}
    MyFileUtil.appendFileName(outputUri, dirName)
  }
  
  /**
   * Determine whether a file is a ZIP File.
   */
  def isZipFile(fileUri: FileResourceUri): Boolean = {
    val file = FileUtil.toFile(fileUri)
    if(file.isDirectory) {
      return false
    }
    if(!file.canRead) {
      throw new IOException("Cannot read file "+file.getAbsolutePath)
    }
    if(file.length() < 4) {
      return false
    }
    val in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))
    val test = in.readInt()
    in.close()
    test == 0x504b0304
  }
  
  /**
   * given an APK file uri, the following method returns the uri of the inner dex file
   */
  def getDexFile(apkUri: FileResourceUri, outputUri: FileResourceUri, createFolder: Boolean): FileResourceUri = {
    val apkFile = FileUtil.toFile(apkUri)
    if(!isZipFile(apkUri)) throw new RuntimeException("File "+ apkFile.getAbsolutePath + " is not a zip File!")
    val zipis = new ZipInputStream(new FileInputStream(apkFile))
    val dirName = apkFile.getName.substring(0, apkFile.getName.lastIndexOf("."))
    val outputDir = getOutputUri(apkUri, outputUri)
    val outputFile = FileUtil.toFile(MyFileUtil.appendFileName(outputDir, dirName + ".dex"))
    val ops = new FileOutputStream(outputFile)
    //resolve with apk file
    while(zipis.available() == 1){
      val ze = zipis.getNextEntry
      if(ze != null)
        if(ze.getName.endsWith(".dex")){
          var reading = true
          while(reading){
            zipis.read() match {
              case -1 => reading = false
              case c => ops.write(c)
            }
          }
        }
    }
    ops.flush()
    zipis.close()
    FileUtil.toUri(outputFile)
  }
  
  def deleteOutputs(apkUri: FileResourceUri, outputUri: FileResourceUri) = {
    val outputDir = FileUtil.toFile(getOutputUri(apkUri, outputUri))
    if(outputDir.exists()){
      MyFileUtil.deleteDir(outputDir)
    }
  }
}
