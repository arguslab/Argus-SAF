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

import java.io._
import java.net.{URI, URLDecoder}
import java.util.jar.JarFile

object FileUtil {

  def toFile(fileUri: FileResourceUri) =
    new File(new URI(fileUri))

  def fileUri(claz: Class[_], path: String): FileResourceUri =
    toUri(new File(claz.getResource(path).toURI))

  def toUri(path: String): FileResourceUri = toUri(new File(path))

  def toUri(f: File): FileResourceUri = f.getCanonicalFile.toURI.toASCIIString

  def toFilePath(fileUri: FileResourceUri): FileResourceUri =
    toFile(fileUri).getAbsolutePath

  def filename(fileUri: FileResourceUri): FileResourceUri =
    toFile(fileUri).getName

  def listFiles(dirUri: FileResourceUri, ext: String,
                recursive: Boolean = false,
                result: MArray[FileResourceUri] = marrayEmpty[FileResourceUri]) //
  : ISeq[FileResourceUri] = {
    val dir = toFile(dirUri)
    if (dir.exists)
      dir.listFiles(new FilenameFilter {
        def accept(dir: File, name: String): Boolean = name.endsWith(ext)
      }).foreach { f => if (f.isFile) result += toUri(f) }
    if (recursive)
      dir.listFiles.foreach { f =>
        if (f.isDirectory) listFiles(toUri(f), ext, recursive, result)
      }
    result.toList
  }

  def readFile(r: java.io.Reader): String = {
    val buffer = new Array[Char](1024)
    var n = r.read(buffer)
    val sb = new StringBuilder
    while (n != -1) {
      sb.appendAll(buffer, 0, n)
      n = r.read(buffer)
    }
    sb.toString
  }

  def writeFile(fileUri: FileResourceUri, content: String): Unit = {
    val fw = new FileWriter(toFile(fileUri))
    try fw.write(content) finally fw.close()
  }

  def readFileContent(fileResourceUri: FileResourceUri): String = {
    val fr = new FileReader(new File(new URI(fileResourceUri)))
    try{
      val lnr = new LineNumberReader(fr)
	    val sb = new StringBuilder
	    var lineText = lnr.readLine
	    while (lineText != null) {
	      sb.append(lineText)
	      sb.append('\n')
	      lineText = lnr.readLine
	    }
      sb.toString
    } finally fr.close()
  }
  
  def deleteDir(dir: File): Boolean = {
    if (dir.isDirectory) {
       val children = dir.list()
       for (i <- 0 until children.length) {
      	 val success = deleteDir(new File(dir, children(i)))
          if (!success) {
             return false
          }
       }
    }
    dir.delete()
  }
  
	/**
   * List directory contents for a resource folder. Not recursive.
   * This is basically a brute-force implementation.
   * Works for regular files and also JARs.
   * 
   * @author Greg Briggs
   * @param clazz Any java class that lives in the same place as the resources you want.
   * @param path Should end with "/", but not start with one.
   * @return Just the name of each member item, not the full paths.
   */
  def getResourceListing[C](clazz: Class[C], path: String, ext: String): ISet[String] = {
      var dirURL = clazz.getResource(path)
      if (dirURL != null && dirURL.getProtocol.equals("file")) {
        /* A file path: easy enough */
        return new File(dirURL.toURI).list().filter(_.endsWith(ext)).toSet
      } 

      if (dirURL == null) {
        /* 
         * In case of a jar file, we can't actually find a directory.
         * Have to assume the same jar as clazz.
         */
        val me = clazz.getName.replace(".", "/")+".class"
        dirURL = clazz.getClassLoader.getResource(me)
      }
      
      if (dirURL.getProtocol.equals("jar")) {
        /* A JAR path */
        val jarPath = dirURL.getPath.substring(5, dirURL.getPath.indexOf("!")) //strip out only the JAR file
        val jar = new JarFile(URLDecoder.decode(jarPath, "UTF-8"))
        val entries = jar.entries() //gives ALL entries in jar
        var result = isetEmpty[String] //avoid duplicates in case it is a subdirectory
        while(entries.hasMoreElements) {
          val name = entries.nextElement().getName
          if (name.startsWith(path) && name.endsWith(ext)) { //filter according to the path
            var entry = name.substring(path.length())
            val checkSubdir = entry.indexOf("/")
            if (checkSubdir >= 0) {
              // if it is a subdirectory, we just return the directory name
              entry = entry.substring(0, checkSubdir)
            }
            result += entry
          }
        }
        return result
      } 
        
      throw new UnsupportedOperationException("Cannot list files for URL "+dirURL)
  }
  
  def listFilesAndDir(dir: File): IList[File] = {
    val result: MList[File] = mlistEmpty
    try {
      val files = dir.listFiles()
      for (file <- files) {
        result += file
        if (file.isDirectory) {
          result ++= listFilesAndDir(file)
        }
      }
    } catch {
      case e: IOException =>
        e.printStackTrace()
    }
    result.toList
  }
  
  def appendFileName(baseUri: FileResourceUri, fileName: String): FileResourceUri = {
    val basePath = FileUtil.toFilePath(baseUri)
    val newPath = s"$basePath${if(!basePath.endsWith(File.separator))File.separator else ""}$fileName"
    FileUtil.toUri(newPath)
  }
}
