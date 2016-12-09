/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import java.io.InputStream

import pxb.android.axml.AxmlVisitor
import org.sireum.util._
import java.io.IOException
import javax.xml.parsers.ParserConfigurationException

import org.xml.sax.SAXException
import javax.xml.parsers.DocumentBuilderFactory

import org.w3c.dom.Node
import brut.androlib.res.data.ResTypeSpec
import brut.androlib.res.data.ResResSpec
import brut.androlib.res.decoder.ARSCDecoder.ARSCData
import org.argus.jawa.core.{Global, JawaClass, JawaType}

/**
 * Parser for analyzing the layout XML files inside an android application
 * 
 * adapted from Steven Arzt
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class LayoutFileParser(global: Global, packageName: String, arsc: ARSCFileParser_apktool) {
  final val TITLE = "LayoutFileParser"
  private final val DEBUG = false

  private final val userControls: MMap[Int, LayoutControl] = mmapEmpty
  private final val callbackMethods: MMap[FileResourceUri, MSet[String]] = mmapEmpty
  private final val includes: MMap[FileResourceUri, MSet[Int]] = mmapEmpty
  
  val data: ARSCData = arsc.getData
  val typs: MMap[String, ResTypeSpec] = mmapEmpty
  import collection.JavaConverters._
  data.getPackages foreach {
    pkg =>
      try {
        val f = pkg.getClass.getDeclaredField("mTypes")
        f.setAccessible(true)
        typs ++= f.get(pkg).asInstanceOf[java.util.LinkedHashMap[String, ResTypeSpec]].asScala
      } catch {
        case ie: InterruptedException => throw ie
        case _: Exception =>
      }
  }
  
//  private final val TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010
//  private final val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
//  private final val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
//  private final val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0

  private def getLayoutClass(className: String): Option[JawaClass] = {
    var ar: Option[JawaClass] = global.getClazz(new JawaType(className))
    if(ar.isEmpty || !this.packageName.isEmpty)
      ar = global.getClazz(new JawaType(packageName + "." + className))
    if(ar.isEmpty)
      ar = global.getClazz(new JawaType("android.widget." + className))
    if(ar.isEmpty)
      ar = global.getClazz(new JawaType("android.webkit." + className))
    if(ar.isEmpty)
      global.reporter.echo(TITLE, "Could not find layout class " + className)
    ar
  }

  private def isLayoutClass(theClass: Option[JawaClass]): Boolean = {
    if (theClass.isEmpty)
      return false
    // To make sure that nothing all wonky is going on here, we
    // check the hierarchy to find the android view class
    var found = false
    global.getClassHierarchy.getAllSuperClassesOf(theClass.get.getType).foreach{
      su =>
        if(su.name.equals("android.view.ViewGroup"))
          found = true
    }
    found
  }

  private def isViewClass(theClass: Option[JawaClass]): Boolean = {
    if (theClass.isEmpty)
      return false
    // To make sure that nothing all wonky is going on here, we
    // check the hierarchy to find the android view class
    global.getClassHierarchy.getAllSuperClassesOf(theClass.get.getType).foreach{
      su =>
      if(su.name.equals("android.view.View") || su.name.equals("android.webkit.WebView"))
        return true
    }
    global.reporter.echo(TITLE, "Layout class " + theClass + " is not derived from " + "android.view.View")
    false
  }
  
  /**
   * Checks whether this name is the name of a well-known Android listener
   * attribute. This is a function to allow for future extension.
   * @param name The attribute name to check. This name is guaranteed to
   * be in the android namespace.
   * @return True if the given attribute name corresponds to a listener,
   * otherwise false.
   */
  private def isActionListener(name: String): Boolean = name.equals("onClick")
  
  private def visitLayoutNode(fileUri: FileResourceUri, n: Node): (Int, Boolean) = {
    var id: Int = -1
    var isSensitive = false
    try {
      val attrs = n.getAttributes
      for(i <- 0 until attrs.getLength) {
        val attr = attrs.item(i)
        val nname = attr.getNodeName
        val ntyp = attr.getNodeType
        val nobj = attr.getNodeValue
        val n = nname.trim
        if(n.endsWith(":id")) {
          val index = nobj.asInstanceOf[String]
          id = getID(index).getOrElse(-1)
        }
        else if(n.endsWith(":password"))
          isSensitive = nobj.asInstanceOf[Int] != 0; // -1 for true, 0 for false
        else if(!isSensitive && n.endsWith(":inputType")) {
          val tp = nobj.asInstanceOf[String]
          isSensitive = tp.contains("Password")
        } else if(isActionListener(n) && ntyp == AxmlVisitor.TYPE_STRING && nobj.isInstanceOf[String]) {
          callbackMethods.getOrElseUpdate(fileUri, msetEmpty) += nobj.asInstanceOf[String]
        } else if(n.endsWith(":layout") && ntyp == AxmlVisitor.TYPE_REFERENCE) {
          this.includes.getOrElseUpdate(fileUri, msetEmpty) += nobj.asInstanceOf[Int]
        } else {
  //        global.reporter.echo(TITLE, "Found unrecognized XML attribute:  " + tempName)
        }
      }
    } catch {
      case ie: InterruptedException => throw ie
      case _: Exception =>
    }
    (id, isSensitive)
  }
  
  private def isIndex(str: String): Boolean = str.startsWith("@")
  
  private def getTypeAndSpec(str: String): (String, String) = {
    val strs = str.substring(1).split("/")
    (strs(0), strs(1))
  }
  
  private def getID(index: String): Option[Int] = {
    if(isIndex(index)) {
      val (typ, spec) = getTypeAndSpec(index)
      typs.get(typ) match {
        case Some(t) =>
          val f = t.getClass.getDeclaredField("mResSpecs")
          f.setAccessible(true)
          val specs = f.get(t).asInstanceOf[java.util.LinkedHashMap[String, ResResSpec]].asScala.toMap
          specs.get(spec) match {
            case Some(s) =>
              return Some(s.getId.id)
            case None =>
          }
        case None =>
      }
    }
    None
  }
  
  def loadLayoutFromTextXml(fileUri: FileResourceUri, layout_in: InputStream): Unit = {
    try {
      val db = DocumentBuilderFactory.newInstance().newDocumentBuilder()
      val doc = db.parse(layout_in)
      val rootElement = doc.getDocumentElement
      val cns = rootElement.getChildNodes
      for(i <- 0 until cns.getLength) {
        val cn = cns.item(i)
        val nname = cn.getNodeName
        val theClass =
          if(nname != null && !nname.startsWith("#")) {
            getLayoutClass(nname.trim())
          } else None
        if (isLayoutClass(theClass) || isViewClass(theClass)) {
          val (id, isSensitive) = visitLayoutNode(fileUri, cn)
          if (id > 0)
            userControls += (id -> LayoutControl(id, theClass.get.getType, isSensitive))
        }
      }
      
    } catch {
      case ex: IOException =>
        System.err.println("Could not parse layout: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
      case ex: ParserConfigurationException =>
        System.err.println("Could not parse layout: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
      case ex: SAXException =>
        System.err.println("Could not parse layout: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
    }
  }

  

  /**
   * Gets the user controls found in the layout XML file. The result is a
   * mapping from the id to the respective layout control.
   * @return The layout controls found in the XML file.
   */
  def getUserControls: IMap[Int, LayoutControl] = this.userControls.toMap

  /**
   * Gets the callback methods found in the layout XML file. The result is a
   * mapping from the file name to the set of found callback methods.
   * @return The callback methods found in the XML file.
   */
  def getCallbackMethods: IMap[FileResourceUri, ISet[String]] = this.callbackMethods.map{case (k, vs) => k -> vs.toSet}.toMap
  
  def getIncludes: IMap[FileResourceUri, ISet[Int]] = this.includes.map{case (k, vs) => k -> vs.toSet}.toMap
}
