/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.amandroid.core.appInfo.ApkCertificate
import org.argus.amandroid.core.decompile.DecompileLayout
import org.argus.amandroid.core.parser.{ComponentInfo, ComponentType, IntentFilterDataBase, LayoutControl}
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._

/**
  * Created by fgwei on 3/12/17.
  */
case class ApkModel(nameUri: FileResourceUri, layout: DecompileLayout) {

  def getAppName: String = FileUtil.toFile(nameUri).getName

  private val certificates: MSet[ApkCertificate] = msetEmpty

  def addCertificates(certs: ISet[ApkCertificate]): Unit = this.certificates ++= certs
  def getCertificates: ISet[ApkCertificate] = this.certificates.toSet

  private val activities: MSet[JawaType] = msetEmpty
  private val nativeActivities: MSet[JawaType] = msetEmpty
  private val services: MSet[JawaType] = msetEmpty
  private val receivers: MSet[JawaType] = msetEmpty
  private val providers: MSet[JawaType] = msetEmpty
  private val dynamicRegisteredReceivers: MSet[JawaType] = msetEmpty

  private val rpcMethods: MMap[JawaType, MMap[Signature, Boolean]] = mmapEmpty

  def addActivity(activity: JawaType): Unit = this.activities += activity
  def addNativeActivity(activity: JawaType): Unit = {
    addActivity(activity)
    this.nativeActivities += activity
  }
  def addService(service: JawaType): Unit = this.services += service
  def addReceiver(receiver: JawaType): Unit = this.receivers += receiver
  def addProvider(provider: JawaType): Unit = this.providers += provider
  def addActivities(activities: ISet[JawaType]): Unit = this.activities ++= activities
  def addServices(services: ISet[JawaType]): Unit = this.services ++= services
  def addReceivers(receivers: ISet[JawaType]): Unit = this.receivers ++= receivers
  def addProviders(providers: ISet[JawaType]): Unit = this.providers ++= providers

  def addRpcMethod(comp: JawaType, rpc: Signature, allow_remote: Boolean): Unit = this.rpcMethods.getOrElseUpdate(comp, mmapEmpty) += (rpc -> allow_remote)
  def addRpcMethods(comp: JawaType, rpcs: IMap[Signature, Boolean]): Unit = this.rpcMethods.getOrElseUpdate(comp, mmapEmpty) ++= rpcs
  def addRpcMethods(map: IMap[JawaType, IMap[Signature, Boolean]]): Unit = map.foreach{case (k, vs) => this.rpcMethods.getOrElseUpdate(k, mmapEmpty) ++= vs}
  def getRpcMethods(comp: JawaType): IMap[Signature, Boolean] = this.rpcMethods.getOrElse(comp, mmapEmpty).toMap
  def getRpcMethods: IMap[Signature, Boolean] = this.rpcMethods.flatMap(_._2).toMap
  def getRpcMethodMapping: IMap[JawaType, IMap[Signature, Boolean]] = this.rpcMethods.map {
    case (k, vs) => k -> vs.toMap
  }.toMap
  def getRpcMethodMappingWithoutRemoteFlag: IMap[JawaType, ISet[Signature]] = this.rpcMethods.map {
    case (k, vs) => k -> vs.keys.toSet
  }.toMap

  def getComponentType(comp: JawaType): Option[AndroidConstants.CompType.Value] = {
    if(activities.contains(comp)) Some(AndroidConstants.CompType.ACTIVITY)
    else if(services.contains(comp)) Some(AndroidConstants.CompType.SERVICE)
    else if(receivers.contains(comp)) Some(AndroidConstants.CompType.RECEIVER)
    else if(providers.contains(comp)) Some(AndroidConstants.CompType.PROVIDER)
    else None
  }

  def addComponent(comp: JawaType, typ: ComponentType.Value): Unit = {
    typ match {
      case ComponentType.ACTIVITY =>
        this.addActivity(comp)
      case ComponentType.SERVICE =>
        this.addService(comp)
      case ComponentType.RECEIVER =>
        this.addReceiver(comp)
      case ComponentType.PROVIDER =>
        this.addProvider(comp)
    }
  }

  def setComponents(comps: ISet[(JawaType, ComponentType.Value)]): Unit = this.synchronized{
    comps.foreach{
      case (ac, typ) =>
        addComponent(ac, typ)
    }
  }

  def getComponents: ISet[JawaType] = (this.activities ++ this.services ++ this.receivers ++ this.providers).toSet
  def getActivities: ISet[JawaType] = this.activities.toSet
  def getNativeActivities: ISet[JawaType] = this.nativeActivities.toSet
  def getServices: ISet[JawaType] = this.services.toSet
  def getReceivers: ISet[JawaType] = this.receivers.toSet
  def getProviders: ISet[JawaType] = this.providers.toSet

  def isNativeActivity(typ: JawaType): Boolean = getNativeActivities.contains(typ)

  def addDynamicRegisteredReceiver(receiver: JawaType): Unit =
    this.synchronized{
      this.dynamicRegisteredReceivers += receiver
      this.receivers += receiver
    }
  def addDynamicRegisteredReceivers(receivers: ISet[JawaType]): Unit =
    this.synchronized{
      this.dynamicRegisteredReceivers ++= receivers
      this.receivers ++= receivers
    }

  def getDynamicRegisteredReceivers: ISet[JawaType] = this.dynamicRegisteredReceivers.toSet

  private val uses_permissions: MSet[String] = msetEmpty
  private val callbackMethods: MMap[JawaType, MSet[Signature]] = mmapEmpty
  private val componentInfos: MSet[ComponentInfo] = msetEmpty
  private val layoutControls: MMap[Int, LayoutControl] = mmapEmpty
  private var appPackageName: String = _
  private val intentFdb: IntentFilterDataBase = new IntentFilterDataBase
  private var codeLineCounter: Int = 0
  /**
    * Map from record name to it's env method code.
    */
  protected val envProcMap: MMap[JawaType, (Signature, String)] = mmapEmpty

  def setCodeLineCounter(c: Int): Unit = this.codeLineCounter = c
  def getCodeLineCounter: Int = this.codeLineCounter
  def setIntentFilterDB(i: IntentFilterDataBase): Unit = this.synchronized{this.intentFdb.reset.merge(i)}
  def updateIntentFilterDB(i: IntentFilterDataBase): Unit = this.synchronized{this.intentFdb.merge(i)}
  def getIntentFilterDB: IntentFilterDataBase = this.intentFdb
  def setPackageName(pn: String): Unit = this.appPackageName = pn
  def getPackageName: String = this.appPackageName
  def addUsesPermissions(ps: ISet[String]): Unit = this.uses_permissions ++= ps
  def getUsesPermissions: ISet[String] = this.uses_permissions.toSet
  def addLayoutControls(i: Int, lc: LayoutControl): Unit = this.layoutControls(i) = lc
  def addLayoutControls(lcs: IMap[Int, LayoutControl]): Unit = this.layoutControls ++= lcs
  def getLayoutControls: IMap[Int, LayoutControl] = this.layoutControls.toMap
  def addCallbackMethods(typ: JawaType, sigs: ISet[Signature]): Unit = this.callbackMethods.getOrElseUpdate(typ, msetEmpty) ++= sigs
  def addCallbackMethods(map: IMap[JawaType, ISet[Signature]]): Unit = map.foreach {case (k, vs) => this.callbackMethods.getOrElseUpdate(k, msetEmpty) ++= vs}
  def getCallbackMethodMapping: IMap[JawaType, ISet[Signature]] = this.callbackMethods.map {
    case (k, vs) => k -> vs.toSet
  }.toMap
  def getCallbackMethods: ISet[Signature] = if(this.callbackMethods.nonEmpty)this.callbackMethods.map(_._2.toSet).reduce(iunion[Signature]) else isetEmpty
  def getCallbackMethods(typ: JawaType): ISet[Signature] = this.callbackMethods.getOrElse(typ, msetEmpty).toSet
  def addComponentInfo(ci: ComponentInfo): Unit = this.componentInfos += ci
  def addComponentInfos(cis: ISet[ComponentInfo]): Unit = this.componentInfos ++= cis
  def getComponentInfos: ISet[ComponentInfo] = this.componentInfos.toSet
  def isExported(component: JawaType): Boolean = getComponentInfos.exists(c => c.compType == component && c.exported)


  def printEnvs(): Unit =
    envProcMap.foreach{case(k, v) => println("Environment for " + k + "\n" + v._2)}

  def printEntrypoints(): Unit = {
    if (this.componentInfos == null)
      println("Entry points not initialized")
    else {
      println("Classes containing entry points:")
      for (record <- componentInfos)
        println("\t" + record)
      println("End of Entrypoints")
    }
  }

  def addEnvMap(typ: JawaType, sig: Signature, code: String): Unit = this.envProcMap(typ) = (sig, code)
  def addEnvMap(envMap: IMap[JawaType, (Signature, String)]): Unit = this.envProcMap ++= envMap
  def getEnvMap: Map[JawaType, (Signature, String)] = this.envProcMap.toMap
  def getEnvString: String = {
    val sb = new StringBuilder
    this.envProcMap.foreach{
      case (k, v) =>
        sb.append("*********************** Environment for " + k + " ************************\n")
        sb.append(v._2 + "\n\n")
    }
    sb.toString.intern()
  }

  def hasEnv(typ: JawaType): Boolean = this.envProcMap.contains(typ)

  def reset(): Unit = {
    this.activities.clear()
    this.nativeActivities.clear()
    this.services.clear()
    this.receivers.clear()
    this.providers.clear()
    this.dynamicRegisteredReceivers.clear()
    this.intentFdb.reset
    this.certificates.clear()
    this.envProcMap.clear()
    this.uses_permissions.clear()
    this.callbackMethods.clear()
    this.componentInfos.clear()
    this.layoutControls.clear()
    this.appPackageName = null
    this.codeLineCounter = 0
  }
}
