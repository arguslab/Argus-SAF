/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core

import java.io._
import java.net.URL
import java.security.{DigestInputStream, MessageDigest}

import org.argus.jawa.core.util.{FileResourceUri, FileUtil, ZipUtil}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidGlobalConfig {

  private val stash_dir = System.getProperty("user.home") + File.separator + ".amandroid_stash"
  final val amandroid_home: String = stash_dir + File.separator + "amandroid"

  final val stash_url = "http://www.fengguow.com/resources/"
  final val BUFFER_SIZE = 1024

  val homeReady: Boolean = checkAmandroidHome
  if(!homeReady){
    errPrintln("Failed to install amandroid_stash. Please report the issue at our issue tracker: https://github.com/arguslab/Argus-SAF/issues")
    sys.exit(-1)
  }
  var iniPathOpt: Option[String] = None

  val settings = new AmandroidSettings(amandroid_home, iniPathOpt)

  def checkAmandroidHome: Boolean = {
    val stash = new File(stash_dir)
    if(!stash.exists()) stash.mkdirs()
    val stash_uri = FileUtil.toUri(stash)
    val remotec = getRemoteChecksum("amandroid.checksum")
    val localCheckUri = FileUtil.appendFileName(stash_uri, "amandroid.checksum")
    val localc = getLocalChecksum(localCheckUri)
    val localfile = FileUtil.toFile(FileUtil.toUri(amandroid_home))
    val localjar = FileUtil.toFile(FileUtil.appendFileName(stash_uri, "amandroid.zip"))
    var needDownload: (Boolean, String) = (false, "")
    if(localfile.exists()) {
      remotec match {
        case Some(rc) =>
          localc match {
            case Some(lc) =>
              if(rc != lc) needDownload = (true, rc)
            case None =>
              needDownload = (true, rc)
          }
        case None =>
      }
    } else {
      remotec match {
        case Some(rc) =>
          needDownload = (true, rc)
        case None =>
      }
    }
    if(needDownload._1) {
      val succ = downloadFile("amandroid.zip", localjar, remotec)
      if(succ) {
        localfile.delete()
        ZipUtil.unZip(localjar.getPath, stash_dir)
        localjar.delete()
        val w = new FileWriter(FileUtil.toFile(localCheckUri), false)
        w.write(needDownload._2)
        w.close()
        true
      } else {
        localjar.delete()
        false
      }
    } else true
  }

  private def updateProgress(progressPercentage: Double, filename: String) {
    val width = 50 // progress bar width in chars

    print("\r[")
    val dots = (progressPercentage*width.toDouble).toInt
    for (_ <- 0 until dots) {
      print(".")
    }
    for (_ <- dots until width) {
      print(" ")
    }
    print(s"]%${(progressPercentage*100).toInt}\t Downloading $filename")
  }

  def outPrintln(s : String) {
    scala.Console.out.println(s)
    scala.Console.out.flush()
  }

  def outPrintln() {
    scala.Console.out.println()
    scala.Console.out.flush()
  }

  def errPrintln(s : String) {
    scala.Console.err.println(s)
    scala.Console.err.flush()
  }

  def errPrintln() {
    scala.Console.err.println()
    scala.Console.err.flush()
  }

  def outPrint(s : String) {
    scala.Console.out.print(s)
    scala.Console.out.flush()
  }

  private def downloadFile(filename: String, file: File, expectedChecksum: Option[String]): Boolean = {
    val httpConnection = new URL(stash_url + filename).openConnection()
    val completeFileSize = httpConnection.getContentLength
    val is = new BufferedInputStream(httpConnection.getInputStream)
    try {
      file.getParentFile.mkdirs
      val os = new BufferedOutputStream(new FileOutputStream(file))
      try {
        val buffer = new Array[Byte](BUFFER_SIZE)
        var n = is.read(buffer)
        var downloadedFileSize: Long = n
        var currentProgress: Double = downloadedFileSize.toDouble / completeFileSize.toDouble
        updateProgress(currentProgress, filename)
        while (n != -1) {
          os.write(buffer, 0, n)
          n = is.read(buffer)
          downloadedFileSize += n
          currentProgress = downloadedFileSize.toDouble / completeFileSize.toDouble
          updateProgress(currentProgress, filename)
        }
        updateProgress(1, filename)
      } finally os.close()
    } finally {
      is.close()
      expectedChecksum.foreach { c =>
        if (getChecksum(file) != c) {
          outPrint("\b\b")
          errPrintln("... failed!")
          file.delete()
          return false
        }
      }
    }
    outPrint("\b\b")
    outPrintln("... done!")
    true
  }

  private def getChecksum(file: File) = {
    val md = MessageDigest.getInstance("MD5")

    val is = new BufferedInputStream(new FileInputStream(file))
    try {
      val dis = new DigestInputStream(is, md)
      while (dis.read != -1) {}
    } finally is.close()

    val digest = md.digest

    val result = new StringBuilder
    for (i <- 0 until digest.length) {
      val s = Integer.toString(digest(i) & 0xff, 16)
      if (s.length == 1) result.append('0')
      result.append(s)
    }

    result.toString
  }

  private def getLocalChecksum(fileUri: FileResourceUri): Option[String] = {
    try {
      val reader = new BufferedReader(new FileReader(FileUtil.toFile(fileUri)))
      val line = reader.readLine()
      Some(line)
    } catch {
      case _: Throwable => None
    }
  }

  private def getRemoteChecksum(fileName: String): Option[String] = {
    try {
      val is = new URL(stash_url + fileName).openStream()
      val in = new BufferedReader(new InputStreamReader(is))
      Some(in.readLine)
    } catch {
      case _: Throwable =>
        errPrintln("Could not connect to update site.")
        errPrintln()
        None
    }
  }
}
