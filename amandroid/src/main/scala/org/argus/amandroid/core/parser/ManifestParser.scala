/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import org.argus.jawa.core.util._
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import javax.xml.parsers.ParserConfigurationException
import org.xml.sax.SAXException
import brut.androlib.res.decoder.AXmlResourceParser
import java.io.File
import java.io.InputStream
import java.io.IOException
import java.io.FileInputStream

import org.argus.jawa.core.elements.JawaType

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class ComponentInfo(compType: JawaType, typ: ComponentType.Value, exported: Boolean, enabled: Boolean, permission: ISet[String], meta_datas: IMap[String, String])

object ComponentType extends Enumeration {
  val ACTIVITY, SERVICE, RECEIVER, PROVIDER = Value
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class ManifestParser{
  final private val DEBUG = false
  private val componentInfos: MSet[ComponentInfo] = msetEmpty
  private val components: MMap[JawaType, ComponentType.Value] = mmapEmpty
  private var packageName = ""
  private val headerNames: MSet[String] = msetEmpty
  private val permissions: MSet[String] = msetEmpty
  private val intentFdb: IntentFilterDataBase = new IntentFilterDataBase
  private var currentComponent: JawaType = _
  private var applicationPermission: String = _
  private val componentPermission: MMap[JawaType, String] = mmapEmpty
  private val componentExported: MMap[JawaType, String] = mmapEmpty
  private val componentEnabled: MMap[JawaType, String] = mmapEmpty
  private val componentMetaData: MMap[JawaType, IMap[String, String]] = mmapEmpty
  private var currentIntentFilter: IntentFilter = _

  private def buildIntentDB(intentFilter: IntentFilter): Unit = {
    intentFdb.updateIntentFmap(intentFilter)
  }

  private def toJawaClass(str: String): JawaType = new JawaType(str)

  def loadClassesFromTextManifest(manifestIS: InputStream): Unit = {
    try {
      val db = DocumentBuilderFactory.newInstance().newDocumentBuilder()
      val doc = db.parse(manifestIS)
      var applicationEnabled = true
      val rootElement = doc.getDocumentElement
      this.packageName = rootElement.getAttribute("package")
      val attributes = rootElement.getAttributes
      if(attributes != null) {
        for(i <- 0 until attributes.getLength){
          val attribute = attributes.item(i)
          if(attribute != null && attribute.toString.startsWith("xmlns:") && attribute.toString.contains("=")) {
            val headername = attribute.toString.substring(attribute.toString.indexOf(":") + 1, attribute.toString.indexOf("="))
            headerNames += headername + ":"
          }
        }
      }
      if(headerNames.isEmpty) headerNames += ""
      val permissions = rootElement.getElementsByTagName("uses-permission")
      for (i <- 0 until permissions.getLength) {
        val permission = permissions.item(i).asInstanceOf[Element]
        headerNames.foreach { header =>
          this.permissions += permission.getAttribute(header + "name")
        }
      }

      val appsElement = rootElement.getElementsByTagName("application")
      for (appIdx <- 0 until appsElement.getLength) {
        val appElement: Element = appsElement.item(appIdx).asInstanceOf[Element]
        // Check whether the application is disabled
        var enabled = ""
        headerNames.foreach {
          header =>
            enabled = appElement.getAttribute(header + "enabled")
        }
        applicationEnabled = enabled.isEmpty || !enabled.equals("false")
        var appperm = ""
        headerNames.foreach {
          header =>
            appperm = appElement.getAttribute(header + "permission")
        }
        if(!appperm.isEmpty)
          this.applicationPermission = appperm
        if(applicationEnabled){
          val activities = appElement.getElementsByTagName("activity")
          val receivers = appElement.getElementsByTagName("receiver")
          val services  = appElement.getElementsByTagName("service")
          val providers = appElement.getElementsByTagName("provider")

          for (i <- 0 until activities.getLength) {
            val activity = activities.item(i).asInstanceOf[Element]
            loadManifestEntry(activity, ComponentType.ACTIVITY, this.packageName)
          }
          for (i <- 0 until receivers.getLength) {
            val receiver = receivers.item(i).asInstanceOf[Element]
            loadManifestEntry(receiver, ComponentType.RECEIVER, this.packageName)
          }
          for (i <- 0 until services.getLength) {
            val service = services.item(i).asInstanceOf[Element]
            loadManifestEntry(service, ComponentType.SERVICE, this.packageName)
          }
          for (i <- 0 until providers.getLength) {
            val provider = providers.item(i).asInstanceOf[Element]
            loadManifestEntry(provider, ComponentType.PROVIDER, this.packageName)
          }
        }
      }
      this.components.foreach{
        case (compType, typ) =>
          val exported = this.componentExported.get(compType) match {
            case Some(tag) =>
              tag match{
                case "false" => false
                case _ => true
              }
            case None =>
              /**
               * from: http://developer.android.com/guide/topics/manifest/provider-element.html
               * For activity, receiver and service:
               * The default value depends on whether the activity contains intent filters.
               * The absence of any filters means that the activity can be invoked only by
               * specifying its exact class name. This implies that the activity is intended
               * only for application-internal use (since others would not know the class name).
               * So in this case, the default value is "false". On the other hand, the presence
               * of at least one filter implies that the activity is intended for external use,
               * so the default value is "true".
               */
              if(typ == ComponentType.ACTIVITY || typ == ComponentType.RECEIVER || typ == ComponentType.SERVICE)
                this.intentFdb.getIntentFilters(compType).nonEmpty
              /**
               * from: http://developer.android.com/guide/topics/manifest/provider-element.html
               * For provider:
               * The default value is "true" for applications that set either android:minSdkVersion
               * or android:targetSdkVersion to "16" or lower. For applications that set either of
               * these attributes to "17" or higher, the default is "false".
               */
              else if(typ == ComponentType.PROVIDER) {
//                this.minSdkVersion <= 16 || this.targetSdkVersion <= 16
                false
              } else throw new RuntimeException("Wrong component type: " + typ)
          }
          val enabled = this.componentEnabled.get(compType) match {
            case Some(tag) =>
              tag match{
                case "false" => false
                case _ => true
              }
            case None =>
              true
          }
          val permission = this.componentPermission.getOrElse(compType, this.applicationPermission)
          val compermission: ISet[String] = if(permission != null && !permission.isEmpty) Set(permission) else Set()
          val metamap: IMap[String, String] = this.componentMetaData.getOrElse(compType, imapEmpty)
          this.componentInfos += ComponentInfo(compType, typ, exported, enabled, compermission, metamap)
      }
    } catch {
      case ex: IOException =>
        System.err.println("Could not parse manifest: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
      case ex: ParserConfigurationException =>
        System.err.println("Could not parse manifest: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
      case ex: SAXException =>
        System.err.println("Could not parse manifest: " + ex.getMessage)
        if(DEBUG)
          ex.printStackTrace()
    }
  }

  private def loadManifestEntry(comp: Element, baseClass: ComponentType.Value, packageName: String): Unit = {
    val className = ManifestParser.getAttribute(comp, "name", ret_null = false, this.headerNames.toSet)
    if (className.startsWith(".")){
      this.currentComponent = toJawaClass(this.packageName + className)
      this.components += (this.currentComponent -> baseClass)
    } else if (this.packageName != "" && !className.contains(".")){
      this.currentComponent = toJawaClass(this.packageName + "." + className)
      this.components += (this.currentComponent -> baseClass)
    } else {
      this.currentComponent = toJawaClass(className)
      this.components += (this.currentComponent -> baseClass)
    }
    val classType = this.currentComponent
    val permission = ManifestParser.getAttribute(comp, "permission", ret_null = false, this.headerNames.toSet)
    if (!permission.isEmpty){
      this.componentPermission += (classType -> permission)
    }
    val exported = ManifestParser.getAttribute(comp, "exported", ret_null = false, this.headerNames.toSet)
    if(!exported.isEmpty){
      this.componentExported += (classType -> exported)
    }
    val enabled = ManifestParser.getAttribute(comp, "enabled", ret_null = false, this.headerNames.toSet)
    if(!enabled.isEmpty){
      this.componentEnabled += (classType -> enabled)
    }
    val metadatas = comp.getElementsByTagName("meta-data")
    val metamap: MMap[String, String] = mmapEmpty
    for (i <- 0 until metadatas.getLength) {
      val metadata = metadatas.item(i).asInstanceOf[Element]
      val key = ManifestParser.getAttribute(metadata, "name", ret_null = false, this.headerNames.toSet)
      val value = ManifestParser.getAttribute(metadata, "value", ret_null = false, this.headerNames.toSet)
      metamap(key) = value
    }
    if(this.currentComponent != null) {
      this.componentMetaData += (this.currentComponent -> metamap.toMap)
    }
    val intentfs = comp.getElementsByTagName("intent-filter")
    for (i <- 0 until intentfs.getLength) {
      val intentfilter = intentfs.item(i).asInstanceOf[Element]
      if(this.currentComponent != null){
        this.currentIntentFilter = new IntentFilter(this.currentComponent)
        buildIntentDB(this.currentIntentFilter)
        val actions = intentfilter.getElementsByTagName("action")
        for (a <- 0 until actions.getLength) {
          if (this.currentIntentFilter != null){
            val action = actions.item(a).asInstanceOf[Element]
            val name = ManifestParser.getAttribute(action, "name", ret_null = false, this.headerNames.toSet)
            val intentF = this.currentIntentFilter
            intentF.addAction(name)              
          }
        }
        val categories = intentfilter.getElementsByTagName("category")
        for (c <- 0 until categories.getLength) {
          if (this.currentIntentFilter != null){
            val category = categories.item(c).asInstanceOf[Element]
            val name = ManifestParser.getAttribute(category, "name", ret_null = false, this.headerNames.toSet)
            val intentF = this.currentIntentFilter
            intentF.addCategory(name)              
          }
        }
        val datas = intentfilter.getElementsByTagName("data")
        for (d <- 0 until datas.getLength) {
          if (this.currentIntentFilter != null){
            val data = datas.item(d).asInstanceOf[Element]
            val scheme = ManifestParser.getAttribute(data, "scheme", ret_null = true, this.headerNames.toSet)
            val host = ManifestParser.getAttribute(data, "host", ret_null = true, this.headerNames.toSet)
            val port = ManifestParser.getAttribute(data, "port", ret_null = true, this.headerNames.toSet)
            val path = ManifestParser.getAttribute(data, "path", ret_null = true, this.headerNames.toSet)
            val pathPrefix = ManifestParser.getAttribute(data, "pathPrefix", ret_null = true, this.headerNames.toSet)
            val pathPattern = ManifestParser.getAttribute(data, "pathPattern", ret_null = true, this.headerNames.toSet)
            val mimeType = ManifestParser.getAttribute(data, "mimeType", ret_null = true, this.headerNames.toSet)
            val intentF = this.currentIntentFilter
            intentF.modData(scheme, host, port, path, pathPrefix, pathPattern, mimeType)
          }
        }
      }
    }
    
    
  }

  def getComponentClasses: ISet[JawaType] = this.components.keySet.toSet

  def getComponentInfos: ISet[ComponentInfo] = this.componentInfos.toSet

  def getPermissions: ISet[String] = this.permissions.toSet

  def getPackageName: String = this.packageName

  def getIntentDB: IntentFilterDataBase = this.intentFdb
}

object ManifestParser {
  def loadPackageName(manifestUri: FileResourceUri): String = {
    try {
      getPackageNameFromManifest(new FileInputStream(FileUtil.toFile(manifestUri)))
    } catch {
      case ie: InterruptedException => throw ie
      case _: Exception =>
        ""
    }
  }
  
  def loadPackageAndComponentNames(manifestUri: FileResourceUri): (String, ISet[(String, String)]) = {
    val db = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    val doc = db.parse(new FileInputStream(FileUtil.toFile(manifestUri)))
    val rootElement = doc.getDocumentElement
    val attributes = rootElement.getAttributes
    val headerNames: MSet[String] = msetEmpty
    if(attributes != null) {
      for(i <- 0 until attributes.getLength){
        val attribute = attributes.item(i)
        if(attribute != null && attribute.toString.startsWith("xmlns:") && attribute.toString.contains("=")) {
          val headername = attribute.toString.substring(attribute.toString.indexOf(":") + 1, attribute.toString.indexOf("="))
          headerNames += headername + ":"
        }
      }
    }
    if(headerNames.isEmpty) headerNames += ""
    val pkg = rootElement.getAttribute("package")
    val recNames: MSet[(String, String)] = msetEmpty
    val appsElement = rootElement.getElementsByTagName("application")
    for (appIdx <- 0 until appsElement.getLength) {
      val appElement: Element = appsElement.item(appIdx).asInstanceOf[Element]
      val className = getAttribute(appElement, "name", ret_null = false, headerNames.toSet)
      recNames += ((className, getClassName(pkg, className)))
      val activities = appElement.getElementsByTagName("activity")
      val receivers = appElement.getElementsByTagName("receiver")
      val services  = appElement.getElementsByTagName("service")
      val providers = appElement.getElementsByTagName("provider")
      for (i <- 0 until activities.getLength) {
        val activity = activities.item(i).asInstanceOf[Element]
        val className = getAttribute(activity, "name", ret_null = false, headerNames.toSet)
        recNames += ((className, getClassName(pkg, className)))
      }
      for (i <- 0 until receivers.getLength) {
        val receiver = receivers.item(i).asInstanceOf[Element]
        val className = getAttribute(receiver, "name", ret_null = false, headerNames.toSet)
        recNames += ((className, getClassName(pkg, className)))
      }
      for (i <- 0 until services.getLength) {
        val service = services.item(i).asInstanceOf[Element]
        val className = getAttribute(service, "name", ret_null = false, headerNames.toSet)
        recNames += ((className, getClassName(pkg, className)))
      }
      for (i <- 0 until providers.getLength) {
        val provider = providers.item(i).asInstanceOf[Element]
        val className = getAttribute(provider, "name", ret_null = false, headerNames.toSet)
        recNames += ((className, getClassName(pkg, className)))
      }
    }
    (pkg, recNames.toSet)
  }
  
  private def getClassName(packageName: String, className: String): String = {
    if (className.startsWith(".")){
      packageName + className
    } else if (!className.isEmpty && className.substring(0, 1).equals(className.substring(0, 1).toUpperCase())){
      packageName + "." + className
    } else if (packageName != "" && !className.contains(".")){
      packageName + "." + className
    } else {
      className
    }
  }
  
  def loadSdkVersionFromManifestFile(apk: File): (Int, Int, Int) = {
    var min: Int = 1
    var target: Int = min
    var max: Int = target
    class MyHandler extends AndroidXMLHandler {
      override def handleXMLFile(fileName: String, fileNameFilter: Set[String], stream: InputStream): Unit = {
        try {
          if (fileNameFilter.contains(fileName)) {
            val (mint, targett, maxt) = getSdkVersionFromBinaryManifest(stream)
            min = mint
            target = targett
            max = maxt
          }
        } catch {
          case ex: IOException =>
            System.err.println("Could not read AndroidManifest file: " + ex.getMessage)
            ex.printStackTrace()
        }
      }
    }
    AndroidXMLParser.handleAndroidXMLFiles(apk, Set("AndroidManifest.xml"), new MyHandler)
    (min, target, max)
  }
  
  protected def getPackageNameFromManifest(manifestIS: InputStream): String = {
    var pkg: String = ""
    try {
      val db = DocumentBuilderFactory.newInstance().newDocumentBuilder()
      val doc = db.parse(manifestIS)
//      var applicationEnabled = true
      val rootElement = doc.getDocumentElement
      pkg = rootElement.getAttribute("package")
    } catch {
      case ie: InterruptedException => throw ie
      case _: Exception =>
    }
    pkg
  }
  
  protected def getSdkVersionFromBinaryManifest(manifestIS: InputStream): (Int, Int, Int) = {
    var min: Int = 1
    var target: Int = min
    var max: Int = target
    try {
      val parser = new AXmlResourceParser()
      parser.open(manifestIS)
      var typ = parser.next()
      while (typ != 0x00000001) { // XmlPullParser.END_DOCUMENT
         typ match {
          case 0x00000000 => // XmlPullParser.START_DOCUMENT
          case 0x00000002 => //XmlPullParser.START_TAG
            val tagName = parser.getName
            if (tagName.equals("uses-sdk")){
              var attrValue = getAttributeValue(parser, "minSdkVersion")
              if (attrValue != null) min = attrValue.toInt
              attrValue = getAttributeValue(parser, "targetSdkVersion")
              if (attrValue != null) target = attrValue.toInt
              attrValue = getAttributeValue(parser, "maxSdkVersion")
              if (attrValue != null) max = attrValue.toInt
            }
            
          case 0x00000003 => //XmlPullParser.END_TAG
          case 0x00000004 => //XmlPullParser.TEXT
        }
        typ = parser.next()
      }
    } catch {
      case ie: InterruptedException => throw ie
      case e: Exception =>
        e.printStackTrace()
    } finally {
      if(min < 1) min = 1
      if(target < min) target = min
      if(max < target) max = target
    }
    (min, target, max)
  }
  
  private def getAttributeValue(parser: AXmlResourceParser, attributeName: String): String = {
    val count = parser.getAttributeCount
    for (i <- 0 until count){
      if (parser.getAttributeName(i).equals(attributeName))
        return parser.getAttributeValue(i)
    }
    null
  }
  
//  private def getAttributeValue(parser: AXmlResourceParser,index: Int): String = {
//    val typ: Int = parser.getAttributeValueType(index)
//    val data: Int = parser.getAttributeValueData(index)
//    if (typ == TypedValue.TYPE_STRING) {
//      return parser.getAttributeValue(index);
//    }
//    if (typ==TypedValue.TYPE_ATTRIBUTE) {
//      val pkg = getPackage(data)
//      return f"?$pkg%s$data%08X"
//    }
//    if (typ==TypedValue.TYPE_REFERENCE) {
//      val pkg = getPackage(data)
//      return f"@$pkg%s$data%08X"
//    }
//    if (typ==TypedValue.TYPE_FLOAT) {
//      return String.valueOf(data.toFloat)
//    }
//    if (typ==TypedValue.TYPE_INT_HEX) {
//      return f"0x$data%08X"
//    }
//    if (typ==TypedValue.TYPE_INT_BOOLEAN) {
//      return if(data!=0)"true"else"false"
//    }
//    if (typ==TypedValue.TYPE_DIMENSION) {
//      return complexToFloat(data) + DIMENSION_UNITS(data & TypedValue.COMPLEX_UNIT_MASK)
//    }
//    if (typ == TypedValue.TYPE_FRACTION) {
//      return complexToFloat(data) + FRACTION_UNITS(data & TypedValue.COMPLEX_UNIT_MASK)
//    }
//    if (typ >= TypedValue.TYPE_FIRST_COLOR_INT && typ<=TypedValue.TYPE_LAST_COLOR_INT) {
//      return f"#$data%08X"
//    }
//    if (typ >= TypedValue.TYPE_FIRST_INT && typ<=TypedValue.TYPE_LAST_INT) {
//      return String.valueOf(data)
//    }
//    return f"<0x$data%X, type 0x$typ%02X>"
//  }
//  
//  private def getPackage(id: Int): String = {
//    if (id>>>24==1) {
//      return "android:"
//    }
//    return ""
//  }
  
  def getAttribute(comp: Element, name: String, ret_null: Boolean, headerNames: ISet[String]): String = {
    var res: String = if(ret_null) null else ""
    headerNames.foreach { header =>
      val x = comp.getAttribute(header + name)
      if(!x.isEmpty) res = x
    }
    res
  }
  
  def complexToFloat(complex: Int): Float = (complex & 0xFFFFFF00)*RADIX_MULTS((complex>>4) & 3)
  
  private final def RADIX_MULTS = List(
    0.00390625F,3.051758E-005F,1.192093E-007F,4.656613E-010F
  )
//  private final def DIMENSION_UNITS = List(
//    "px","dip","sp","pt","in","mm","",""
//  )
//  private final def FRACTION_UNITS = List(
//    "%","%p","","","","","",""
//  )
}
