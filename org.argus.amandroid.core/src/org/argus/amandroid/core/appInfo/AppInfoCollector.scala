/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.appInfo

import org.sireum.util._

import scala.util.control.Breaks._
import java.io.FileInputStream

import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.amandroid.core.parser._
import org.argus.amandroid.core.pilarCodeGenerator.{AndroidEntryPointConstants, AndroidEnvironmentGenerator, AndroidSubstituteClassMap}
import org.argus.jawa.core._
import org.argus.jawa.core.util.MyFileUtil

/** 
 * adapted from Steven Arzt of the FlowDroid group
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object AppInfoCollector {
  final val TITLE = "AppInfoCollector"
  
  def readCertificates(apkUri: FileResourceUri): ISet[ApkCertificate] = {
    ApkCertificateReader(apkUri)
  }
  
  def analyzeManifest(reporter: Reporter, manifestUri: FileResourceUri): ManifestParser = {
    val manifestIS = new FileInputStream(FileUtil.toFile(manifestUri))
    val mfp = new ManifestParser
    mfp.loadClassesFromTextManifest(manifestIS)
    manifestIS.close()
    reporter.echo(TITLE, "entrypoints--->" + mfp.getComponentClasses)
    reporter.echo(TITLE, "packagename--->" + mfp.getPackageName)
    reporter.echo(TITLE, "permissions--->" + mfp.getPermissions)
    reporter.echo(TITLE, "intentDB------>" + mfp.getIntentDB)
    mfp
  }

  def analyzeARSC(reporter: Reporter, apkUri: FileResourceUri): ARSCFileParser_apktool = {
    // Parse the resource file
    val afp = new ARSCFileParser_apktool()
    afp.parse(apkUri)
    reporter.echo(TITLE, "arscstring-->" + afp.getGlobalStringPool)
    reporter.echo(TITLE, "arscpackage-->" + afp.getPackages)
    afp
  }

  def analyzeLayouts(global: Global, outputUri: FileResourceUri, mfp: ManifestParser, afp: ARSCFileParser_apktool): LayoutFileParser = {
    // Find the user-defined sources in the layout XML files
    val lfp = new LayoutFileParser(global, mfp.getPackageName, afp)
    FileUtil.listFiles(outputUri, ".xml", recursive = true).foreach {
      u =>
        if(u.contains("/res/layout")) {
          val file = FileUtil.toFile(u)
          val layout_in = new FileInputStream(file)
          lfp.loadLayoutFromTextXml(file.getName, layout_in)
        }
    }
    global.reporter.echo(TITLE, "layoutcallback--->" + lfp.getCallbackMethods)
    global.reporter.echo(TITLE, "layoutuser--->" + lfp.getUserControls)
    lfp
  }

  def analyzeCallback(reporter: Reporter, afp: ARSCFileParser_apktool, lfp: LayoutFileParser, analysisHelper: ReachableInfoCollector): IMap[JawaType, ISet[Signature]] = {
    val callbackMethods: MMap[JawaType, MSet[Signature]] = mmapEmpty
    analysisHelper.collectCallbackMethods()
    reporter.echo(TITLE, "LayoutClasses --> " + analysisHelper.getLayoutClasses)
  
    analysisHelper.getCallbackMethods.foreach {
      case(k, v) =>
        callbackMethods.getOrElseUpdate(k, msetEmpty) ++= v
    }
    // Collect the XML-based callback methods
    analysisHelper.getLayoutClasses.foreach {
      case (k, v) =>
        v.foreach {
          i =>
            val resource = afp.findResource(i)
            if(resource != null && resource.getType.getName == "layout"){
              val includes = lfp.getIncludes.filter(_._1.contains(resource.getName)).flatten(_._2).toSet
              val resources = includes.map(i => afp.findResource(i)) + resource
              lfp.getCallbackMethods.find{case (file, _) => resources.map(_.getName).exists { x => file.contains(x) }}.foreach{
                case (_, methodNames) =>
                  for(methodName <- methodNames) {
                    //The callback may be declared directly in the class or in one of the superclasses
                    var callbackClass = analysisHelper.global.getClassOrResolve(k)
                    val callbackMethod: MSet[Signature] = msetEmpty
                    breakable{ 
                      while(callbackMethod.isEmpty){
                        if(callbackClass.declaresMethodByName(methodName))
                          callbackMethod ++= callbackClass.getDeclaredMethodsByName(methodName).map(_.getSignature)
                        if(callbackClass.hasSuperClass)
                          callbackClass = callbackClass.getSuperClass.get
                        else break
                      }
                    }
                    if(callbackMethod.nonEmpty){
                      callbackMethods.getOrElseUpdate(k, msetEmpty) ++= callbackMethod
                    } else {
                      reporter.echo(TITLE, "Callback method " + methodName + " not found in class " + k)
                    }
                  }
              }
          } else {
            reporter.echo(TITLE, "Unexpected resource type for layout class: " + resource)
          }
      }
    }
    callbackMethods.map{
      case (c, ms) => 
        c -> ms.toSet
    }.toMap
  }

  def reachabilityAnalysis(global: Global, typs: ISet[JawaType]): ReachableInfoCollector = {
    // Collect the callback interfaces implemented in the app's source code
    val analysisHelper = new ReachableInfoCollector(global, typs) 
    analysisHelper.init()
    //  this.sensitiveLayoutContainers = analysisHelper.getSensitiveLayoutContainer(this.layoutControls)
    analysisHelper
  }

  def generateEnvironment(apk: Apk, record: JawaClass, envName: String, reporter: Reporter): Int = {
    if(record == null) return 0
    //generate env main method
    reporter.echo(TITLE, "Generate environment for " + record)
    val dmGen = new AndroidEnvironmentGenerator(record.global)
    dmGen.setSubstituteClassMap(AndroidSubstituteClassMap.getSubstituteClassMap)
    dmGen.setCurrentComponent(record.getType)
    dmGen.setComponentInfos(apk.getComponentInfos)
    dmGen.setCodeCounter(apk.getCodeLineCounter)
    dmGen.setCallbackFunctions(apk.getCallbackMethodMapping)
    val (proc, code) = dmGen.generateWithParam(List(new JawaType(AndroidEntryPointConstants.INTENT_NAME)), envName)
    apk.addEnvMap(record.getType, proc.getSignature, code)
    dmGen.getCodeCounter
  }

  def dynamicRegisterReceiver(apk: Apk, comRec: JawaClass, iDB: IntentFilterDataBase, permission: ISet[String], reporter: Reporter) = {
    this.synchronized{
      if(!comRec.declaresMethodByName(AndroidConstants.COMP_ENV)){
        reporter.echo(TITLE, "*************Dynamically Register Component**************")
        reporter.echo(TITLE, "Component name: " + comRec)
        apk.updateIntentFilterDB(iDB)
        AppInfoCollector.reachabilityAnalysis(comRec.global, Set(comRec.getType)).getCallbackMethods foreach {
          case (typ, sigs) => apk.addCallbackMethods(typ, sigs)
        }
        reporter.echo(TITLE, "Found " + apk.getCallbackMethods.size + " callback methods")
        val clCounter = generateEnvironment(apk, comRec, AndroidConstants.COMP_ENV, reporter)
        apk.setCodeLineCounter(clCounter)
        apk.addComponentInfo(ComponentInfo(comRec.getType, ComponentType.RECEIVER, exported = true, enabled = true, permission))
        apk.addDynamicRegisteredReceiver(comRec.getType)
        apk.updateIntentFilterDB(iDB)
        reporter.echo(TITLE, "~~~~~~~~~~~~~~~~~~~~~~~~~Done~~~~~~~~~~~~~~~~~~~~~~~~~~")
      }
    }
  }
  
  /**
   * Get rpc method list for Android component
   * originally designed by Sankardas Roy, modified by Fengguo Wei
   */
  def getRpcMethods(apk: Apk, comp: JawaClass): ISet[JawaMethod] = {
    if(apk.getServices.contains(comp.getType)){
      comp.getDeclaredMethods.filter { 
        method => 
          !(method.isConstructor || AndroidEntryPointConstants.getServiceLifecycleMethods.contains(method.getSubSignature)
              || method.getName == AndroidConstants.MAINCOMP_ENV || method.getName == AndroidConstants.COMP_ENV) 
      }
    } else isetEmpty
  }

  def collectInfo(apk: Apk, global: Global, outUri: FileResourceUri): Unit = {
    val certs = AppInfoCollector.readCertificates(apk.nameUri)
    val manifestUri = MyFileUtil.appendFileName(outUri, "AndroidManifest.xml")
    val mfp = AppInfoCollector.analyzeManifest(global.reporter, manifestUri)
    val afp = AppInfoCollector.analyzeARSC(global.reporter, apk.nameUri)
    val lfp = AppInfoCollector.analyzeLayouts(global, outUri, mfp, afp)
    val ra = AppInfoCollector.reachabilityAnalysis(global, mfp.getComponentInfos.map(_.compType))
    val callbacks = AppInfoCollector.analyzeCallback(global.reporter, afp, lfp, ra)
    apk.addCertificates(certs)
    apk.setPackageName(mfp.getPackageName)
    apk.addComponentInfos(mfp.getComponentInfos)
    apk.addUsesPermissions(mfp.getPermissions)
    apk.updateIntentFilterDB(mfp.getIntentDB)
    apk.addLayoutControls(lfp.getUserControls)
    callbacks foreach {
      case (typ, sigs) => apk.addCallbackMethods(typ, sigs)
    }
    val components = msetEmpty[(JawaClass, ComponentType.Value)]
    mfp.getComponentInfos.foreach {
      f =>
        if(f.enabled){
          val comp = global.getClassOrResolve(f.compType)
          if(!comp.isUnknown && comp.isApplicationClass){
            components += ((comp, f.typ))
            val clCounter = generateEnvironment(apk, comp, if(f.exported)AndroidConstants.MAINCOMP_ENV else AndroidConstants.COMP_ENV, global.reporter)
            apk.setCodeLineCounter(clCounter)
          }
        }
    }
    components.foreach {
      comp =>
        val rpcs = getRpcMethods(apk, comp._1)
        apk.addRpcMethods(comp._1.getType, rpcs.map(_.getSignature))
    }
    apk.setComponents(components.map{case (a, b) => (a.getType, b)}.toSet)
    global.reporter.echo(TITLE, "Entry point calculation done.")
  }
}
