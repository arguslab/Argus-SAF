/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.jawa.core.util._

import org.argus.amandroid.core.model.ApkModel
import org.argus.amandroid.core.appInfo.ApkCertificate
import org.argus.amandroid.core.parser.{ComponentInfo, ComponentType, IntentFilterDataBase, LayoutControl}
import org.argus.jawa.core._
import org.json4s.{CustomSerializer, Extraction, JValue}
import org.json4s.JsonDSL._

object ApkModelSerializer extends CustomSerializer[ApkModel](format => (
  {
    case jv: JValue =>
      implicit val formats = format + JawaTypeSerializer + JawaTypeKeySerializer + SignatureSerializer + SignatureKeySerializer + IntentFilterDataBaseSerializer + new org.json4s.ext.EnumNameSerializer(ComponentType)
      val nameUri  = (jv \ "nameUri").extract[FileResourceUri]
      val outApkUri = (jv \ "outApkUri").extract[FileResourceUri]
      val srcs = (jv \ "srcs").extract[ISet[String]]
      val certificates = (jv \ "certificates").extract[ISet[ApkCertificate]]
      val activities = (jv \ "activities").extract[ISet[JawaType]]
      val services = (jv \ "services").extract[ISet[JawaType]]
      val receivers = (jv \ "receivers").extract[ISet[JawaType]]
      val providers = (jv \ "provider").extract[ISet[JawaType]]
      val drReceivers = (jv \ "drReceivers").extract[ISet[JawaType]]
      val rpcMethods = (jv \ "rpcMethods").extract[IMap[JawaType, IMap[Signature, Boolean]]]
      val uses_permissions = (jv \ "uses_permissions").extract[ISet[String]]
      val callbackMethods = (jv \ "callbackMethods").extract[IMap[JawaType, ISet[Signature]]]
      val componentInfos = (jv \ "componentInfos").extract[ISet[ComponentInfo]]
      val layoutControls = (jv \ "layoutControls").extract[IMap[Int, LayoutControl]]
      val appPackageName = (jv \ "appPackageName").extract[Option[String]]
      val intentFdb = (jv \ "intentFdb").extract[IntentFilterDataBase]
      val codeLineCounter = (jv \ "codeLineCounter").extract[Int]
      val envMap = (jv \ "envMap").extract[IMap[JawaType, (Signature, String)]]
      val apk = ApkModel(nameUri, outApkUri, srcs)
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
    case model: ApkModel =>
      implicit val formats = format + JawaTypeSerializer + JawaTypeKeySerializer + SignatureSerializer + SignatureKeySerializer + IntentFilterDataBaseSerializer + new org.json4s.ext.EnumNameSerializer(ComponentType)
      val nameUri: FileResourceUri = model.nameUri
      val outApkUri: FileResourceUri = model.outApkUri
      val srcs: ISet[String] = model.srcs
      val certificates: ISet[ApkCertificate] = model.getCertificates
      val activities: ISet[JawaType] = model.getActivities
      val services: ISet[JawaType] = model.getServices
      val receivers: ISet[JawaType] = model.getReceivers
      val providers: ISet[JawaType] = model.getProviders
      val drReceivers: ISet[JawaType] = model.getDynamicRegisteredReceivers
      val rpcMethods: IMap[JawaType, IMap[Signature, Boolean]] = model.getRpcMethodMapping
      val uses_permissions: ISet[String] = model.getUsesPermissions
      val callbackMethods: IMap[JawaType, ISet[Signature]] = model.getCallbackMethodMapping
      val componentInfos: ISet[ComponentInfo] = model.getComponentInfos
      val layoutControls: IMap[Int, LayoutControl] = model.getLayoutControls
      val appPackageName: String = model.getPackageName
      val intentFdb: IntentFilterDataBase = model.getIntentFilterDB
      val codeLineCounter: Int = model.getCodeLineCounter
      val envMap: IMap[JawaType, (Signature, String)] = model.getEnvMap
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