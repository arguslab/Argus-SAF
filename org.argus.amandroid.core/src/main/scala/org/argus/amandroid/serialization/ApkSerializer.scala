/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.json4s.native.Serialization.{read, write}
import org.sireum.util._
import java.io.FileReader
import java.io.FileWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.{AndroidGlobalConfig, Apk}
import org.argus.amandroid.core.appInfo.ApkCertificate
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.parser.{ComponentInfo, ComponentType, IntentFilterDataBase, LayoutControl}
import org.argus.jawa.core._
import org.argus.jawa.core.util.MyFileUtil
import org.json4s.native.Serialization
import org.json4s.{CustomSerializer, Extraction, JValue, NoTypeHints}
import org.json4s.JsonDSL._

object ApkSerializer extends CustomSerializer[Apk](format => (
  {
    case jv: JValue =>
      implicit val formats = format + JawaTypeSerializer + JawaTypeKeySerializer + SignatureSerializer + IntentFilterDataBaseSerializer + new org.json4s.ext.EnumNameSerializer(ComponentType)
      val nameUri  = (jv \ "nameUri").extract[FileResourceUri]
      val outApkUri = (jv \ "outApkUri").extract[FileResourceUri]
      val srcs = (jv \ "srcs").extract[ISet[String]]
      val certificates = (jv \ "certificates").extract[ISet[ApkCertificate]]
      val activities = (jv \ "activities").extract[ISet[JawaType]]
      val services = (jv \ "services").extract[ISet[JawaType]]
      val receivers = (jv \ "receivers").extract[ISet[JawaType]]
      val providers = (jv \ "provider").extract[ISet[JawaType]]
      val drReceivers = (jv \ "drReceivers").extract[ISet[JawaType]]
      val rpcMethods = (jv \ "rpcMethods").extract[IMap[JawaType, ISet[Signature]]]
      val uses_permissions = (jv \ "uses_permissions").extract[ISet[String]]
      val callbackMethods = (jv \ "callbackMethods").extract[IMap[JawaType, ISet[Signature]]]
      val componentInfos = (jv \ "componentInfos").extract[ISet[ComponentInfo]]
      val layoutControls = (jv \ "layoutControls").extract[IMap[Int, LayoutControl]]
      val appPackageName = (jv \ "appPackageName").extract[Option[String]]
      val intentFdb = (jv \ "intentFdb").extract[IntentFilterDataBase]
      val codeLineCounter = (jv \ "codeLineCounter").extract[Int]
      val envMap = (jv \ "envMap").extract[IMap[JawaType, (Signature, String)]]
      val apk = new Apk(nameUri, outApkUri, srcs)
      apk.addCertificates(certificates)
      apk.addActivities(activities)
      apk.addServices(services)
      apk.addReceivers(receivers)
      apk.addProviders(providers)
      apk.addDynamicRegisteredReceivers(drReceivers)
      apk.addRpcMethods(rpcMethods)
      apk.addUsesPermissions(uses_permissions)
      apk.addCallbackMethods(callbackMethods)
      apk.addComponentInfos(componentInfos)
      apk.addLayoutControls(layoutControls)
      apk.setPackageName(appPackageName.getOrElse(""))
      apk.setIntentFilterDB(intentFdb)
      apk.setCodeLineCounter(codeLineCounter)
      apk.addEnvMap(envMap)
      apk
  },
  {
    case apk: Apk =>
      implicit val formats = format + JawaTypeSerializer + JawaTypeKeySerializer + SignatureSerializer + IntentFilterDataBaseSerializer + new org.json4s.ext.EnumNameSerializer(ComponentType)
      val nameUri: FileResourceUri = apk.nameUri
      val outApkUri: FileResourceUri = apk.outApkUri
      val srcs: ISet[String] = apk.srcs
      val certificates: ISet[ApkCertificate] = apk.getCertificates
      val activities: ISet[JawaType] = apk.getActivities
      val services: ISet[JawaType] = apk.getServices
      val receivers: ISet[JawaType] = apk.getReceivers
      val providers: ISet[JawaType] = apk.getProviders
      val drReceivers: ISet[JawaType] = apk.getDynamicRegisteredReceivers
      val rpcMethods: IMap[JawaType, ISet[Signature]] = apk.getRpcMethodMapping
      val uses_permissions: ISet[String] = apk.getUsesPermissions
      val callbackMethods: IMap[JawaType, ISet[Signature]] = apk.getCallbackMethodMapping
      val componentInfos: ISet[ComponentInfo] = apk.getComponentInfos
      val layoutControls: IMap[Int, LayoutControl] = apk.getLayoutControls
      val appPackageName: String = apk.getPackageName
      val intentFdb: IntentFilterDataBase = apk.getIntentFilterDB
      val codeLineCounter: Int = apk.getCodeLineCounter
      val envMap: IMap[JawaType, (Signature, String)] = apk.getEnvMap
      ("nameUri" -> nameUri) ~
      ("outApkUri" -> outApkUri) ~
      ("srcs" -> srcs) ~
      ("certificates" -> Extraction.decompose(certificates)) ~
      ("activities" -> Extraction.decompose(activities)) ~
      ("services" -> Extraction.decompose(services)) ~
      ("receivers" -> Extraction.decompose(receivers)) ~
      ("providers" -> Extraction.decompose(providers)) ~
      ("drReceivers" -> Extraction.decompose(drReceivers)) ~
      ("rpcMethods" -> Extraction.decompose(rpcMethods)) ~
      ("uses_permissions" -> Extraction.decompose(uses_permissions)) ~
      ("callbackMethods" -> Extraction.decompose(callbackMethods)) ~
      ("componentInfos" -> Extraction.decompose(componentInfos)) ~
      ("layoutControls" -> Extraction.decompose(layoutControls)) ~
      ("appPackageName" -> Option(appPackageName)) ~
      ("intentFdb" -> Extraction.decompose(intentFdb)) ~
      ("codeLineCounter" -> codeLineCounter) ~
      ("envMap" -> Extraction.decompose(envMap))
  }
))

object ApkSerTest {
  def main(args: scala.Array[String]): Unit = {
    val apkPath = args(0)
    val outputPath = args(1)
    val apkUri = FileUtil.toUri(apkPath)
    val outputUri = FileUtil.toUri(outputPath)
    val reporter = new PrintReporter(MsgLevel.ERROR)
    val global = new Global(apkUri, reporter)
    global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
    val yard = new ApkYard(global)
    val layout = DecompileLayout(outputUri)
    val settings = DecompilerSettings(None, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = true, None, layout)
    val apk = yard.loadApk(apkUri, settings)
    println(apk.getCertificates)
    implicit val formats = Serialization.formats(NoTypeHints) + ApkSerializer
    val apkRes = FileUtil.toFile(MyFileUtil.appendFileName(outputUri, "apk.json"))
    val oapk = new FileWriter(apkRes)
    try {
      write(apk, oapk)
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      oapk.flush()
      oapk.close()
    }
    val iapk = new FileReader(apkRes)
    try {
      val apk = read[Apk](iapk)
      println(apk.getCertificates)
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      iapk.close()
    }
  }
}