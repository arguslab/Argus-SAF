/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import pxb.android.axml.AxmlVisitor.NodeVisitor
import pxb.android.axml.AxmlVisitor
import pxb.android.axml.AxmlReader
import java.io.ByteArrayOutputStream
import org.sireum.util._
import java.io.InputStream
import java.io.File
import java.net.URI

/**
 * Parser for analyzing the resource XML files inside an android application
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class ResourceFileParser {
  final val TITLE = "ResourceFileParser"
  private final val DEBUG = false
  
  private val strs: MSet[String] = msetEmpty
  
  def getAllStrings: Set[String] = this.strs.toSet
  
  private class ResourceParser(resFile: String) extends NodeVisitor {
            
    
    override def child(ns: String, name: String): NodeVisitor = {
      if (name == null) {
//        err_msg_detail(TITLE, "Encountered a null node name "
//            + "in file " + resFile + ", skipping node...")
        return null
      }
      new ResourceParser(resFile)
        //super.child(ns, name);
    }
    
    override def attr(ns: String, name: String, resourceId: Int, typ: Int, obj: Object): Unit = {
      // Check that we're actually working on an android attribute
      if (ns == null)
        return
      //println("ns: " + ns)
      var tempNS = ns
      tempNS = tempNS.trim()
      if (tempNS.startsWith("*"))
        tempNS = tempNS.substring(1)
      if (!tempNS.equals("http://schemas.android.com/apk/res/android"))
        return

      // Read out the field data
      var tempName = name
      tempName = tempName.trim()
      //println("name: " + name)
      //println("obj: " + obj)
      if (typ == AxmlVisitor.TYPE_STRING && obj.isInstanceOf[String]) {
        val strData = obj.asInstanceOf[String].trim();
        strs += strData
      }
    }
  }
  
  /**
   * Parses all resource XML files in the given APK file.
   * @param fileName The APK file
   */
  def parseResourceFile(apkUri: FileResourceUri) {
    AbstractAndroidXMLParser.handleAndroidXMLFiles(new File(new URI(apkUri)), null, new AndroidXMLHandler() {
      override def handleXMLFile(fileName: String, fileNameFilter: Set[String], stream: InputStream): Unit = {
        // We only process valid layout XML files
        if (!fileName.startsWith("res/"))
          return
        if (!fileName.endsWith(".xml")) {
//              err_msg_normal(TITLE, "Skipping file " + fileName + " in resource folder...")
          return
        }
        //println("filename: " + fileName)
        // Get the fully-qualified class name
        var entryClass = fileName.substring(0, fileName.lastIndexOf("."))
        try {
          val bos = new ByteArrayOutputStream();
          var in: Int = 0
          in = stream.read()
          while (in >= 0){
            bos.write(in)
            in = stream.read()
          }
          bos.flush()
          val data = bos.toByteArray()
          if (data == null || data.length == 0)  // File empty?
            return
          
          val rdr = new AxmlReader(data)
          rdr.accept(new AxmlVisitor() {
            
            override def first(ns: String, name: String): NodeVisitor = {
              new ResourceParser(fileName)
            }
          })
        }
        catch {
          case ie: InterruptedException => throw ie
          case ex: Exception =>
//                err_msg_detail(TITLE, "Could not read binary XML file: " + ex.getMessage())
        }
      }
    })
  }
}
