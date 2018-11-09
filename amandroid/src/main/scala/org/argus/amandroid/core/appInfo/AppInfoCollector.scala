/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.appInfo

import org.argus.jawa.core.util._

import scala.util.control.Breaks._
import java.io.FileInputStream

import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser._
import org.argus.amandroid.core.codegen.{AndroidEntryPointConstants, AndroidEnvironmentGenerator, AndroidSubstituteClassMap, AsyncTaskEnvGenerator}
import org.argus.amandroid.core.util.GuessAppPackages
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util.FileUtil

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
    reporter.println("Read AndroidManifest.")
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
    reporter.println("Read ARSC.")
    // Parse the resource file
    val afp = new ARSCFileParser_apktool()
    afp.parse(apkUri)
    reporter.echo(TITLE, "arscstring-->" + afp.getGlobalStringPool)
    reporter.echo(TITLE, "arscpackage-->" + afp.getPackages)
    afp
  }

  def analyzeLayouts(apk: ApkGlobal, outputUri: FileResourceUri, mfp: ManifestParser, afp: ARSCFileParser_apktool): LayoutFileParser = {
    apk.reporter.println(s"Read Layout files.")
    // Find the user-defined sources in the layout XML files
    val lfp = new LayoutFileParser(apk, mfp.getPackageName, afp)
    FileUtil.listFiles(outputUri, ".xml", recursive = true).foreach {
      u =>
        if(u.contains("/res/layout")) {
          val file = FileUtil.toFile(u)
          val layout_in = new FileInputStream(file)
          lfp.loadLayoutFromTextXml(file.getName, layout_in)
        }
    }
    apk.reporter.echo(TITLE, "layoutcallback--->" + lfp.getCallbackMethods)
    apk.reporter.echo(TITLE, "layoutuser--->" + lfp.getUserControls)
    lfp
  }

  def analyzeCallback(reporter: Reporter, afp: ARSCFileParser_apktool, lfp: LayoutFileParser, analysisHelper: ReachableInfoCollector): IMap[JawaType, ISet[Signature]] = {
    reporter.println("Analyzing callbacks...")
    val callbackMethods: MMap[JawaType, MSet[Signature]] = mmapEmpty
    analysisHelper.collectCallbackMethods()
    reporter.echo(TITLE, "LayoutClasses --> " + analysisHelper.getLayoutClasses)
  
    analysisHelper.getCallbackMethods.foreach { case(k, v) =>
      callbackMethods.getOrElseUpdate(k, msetEmpty) ++= v
    }
    reporter.println("Collecting XML based callback methods...")
    // Collect the XML-based callback methods
    analysisHelper.getLayoutClasses.foreach { case (k, v) =>
      v.foreach { i =>
        val resource = afp.findResource(i)
        if(resource != null && resource.getType.getName == "layout") {
          val includes = lfp.getIncludes.filter(_._1.contains(resource.getName)).flatten(_._2).toSet
          val resources = includes.map(i => afp.findResource(i)) + resource
          lfp.getCallbackMethods.find{case (file, _) => resources.map(_.getName).exists { x => file.contains(x) }}.foreach{
            case (_, methodNames) =>
              for(methodName <- methodNames) {
                //The callback may be declared directly in the class or in one of the superclasses
                var callbackClass = analysisHelper.global.getClassOrResolve(k)
                val callbackMethod: MSet[Signature] = msetEmpty
                breakable{
                  while(callbackMethod.isEmpty) {
                    if(callbackClass.declaresMethodByName(methodName))
                      callbackMethod ++= callbackClass.getDeclaredMethodsByName(methodName).map(_.getSignature)
                    if(callbackClass.hasSuperClass)
                      callbackClass = callbackClass.getSuperClass
                    else break
                  }
                }
                if(callbackMethod.nonEmpty) {
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
    reporter.println("Callback collection done.")
    callbackMethods.map{
      case (c, ms) => 
        c -> ms.toSet
    }.toMap
  }

  def reachabilityAnalysis(global: Global, typs: ISet[JawaType]): ReachableInfoCollector = {
    global.reporter.println("Start reachabilityAnalysis...")
    // Collect the callback interfaces implemented in the app's source code
    val analysisHelper = new ReachableInfoCollector(global, typs) 
    analysisHelper.init()
    global.reporter.println("ReachabilityAnalysis done.")
    analysisHelper
  }

  def generateEnvironment(apk: ApkGlobal, clazz: JawaClass, envName: String): Int = {
    if(clazz == null) return 0
    //generate env main method
    apk.reporter.echo(TITLE, "Generate environment for " + clazz)
    val dmGen = new AndroidEnvironmentGenerator(apk)
    dmGen.setSubstituteClassMap(AndroidSubstituteClassMap.getSubstituteClassMap)
    dmGen.setCurrentComponent(clazz.getType)
    dmGen.setComponentInfos(apk.model.getComponentInfos)
    dmGen.setCodeCounter(apk.model.getCodeLineCounter)
    dmGen.setCallbackFunctions(apk.model.getCallbackMethodMapping)
    dmGen.setCallbackFunctions(apk.model.getRpcMethodMappingWithoutRemoteFlag)
    val (proc, code) = dmGen.generateWithParam(List((new JawaType(AndroidEntryPointConstants.INTENT_NAME), "object")), List(), envName, "STATIC")
    apk.model.addEnvMap(clazz.getType, proc.getSignature, code)
    dmGen.getCodeCounter
  }

  def generateAsyncTask(apk: ApkGlobal, typ: JawaType): Unit = {
    apk.reporter.echo("generateAsyncTask", "Generate environment for " + typ)
    val dmGen = new AsyncTaskEnvGenerator(apk)
    dmGen.setSubstituteClassMap(AndroidSubstituteClassMap.getSubstituteClassMap)
    dmGen.setCurrentComponent(typ)
    dmGen.generateWithParam(List((typ, "this"), (JawaType.addDimensions(JavaKnowledge.OBJECT, 1), "object")), List(), "run", "PUBLIC")
  }

  def dynamicRegisterReceiver(apk: ApkGlobal, comRec: JawaClass, iDB: IntentFilterDataBase, permission: ISet[String]): Unit = {
    this.synchronized{
      if(!comRec.declaresMethodByName(AndroidConstants.COMP_ENV)){
        apk.reporter.println(s"Register receiver ${comRec.getName}")
        apk.reporter.echo(TITLE, "*************Dynamically Register Component**************")
        apk.reporter.echo(TITLE, "Component name: " + comRec)
        apk.model.updateIntentFilterDB(iDB)
        AppInfoCollector.reachabilityAnalysis(comRec.global, Set(comRec.getType)).getCallbackMethods foreach {
          case (typ, sigs) => apk.model.addCallbackMethods(typ, sigs)
        }
        apk.reporter.echo(TITLE, "Found " + apk.model.getCallbackMethods.size + " callback methods")
        val clCounter = generateEnvironment(apk, comRec, AndroidConstants.COMP_ENV)
        apk.model.setCodeLineCounter(clCounter)
        apk.model.addComponentInfo(ComponentInfo(comRec.getType, ComponentType.RECEIVER, exported = true, enabled = true, permission, imapEmpty))
        apk.model.addDynamicRegisteredReceiver(comRec.getType)
        apk.model.updateIntentFilterDB(iDB)
        apk.reporter.echo(TITLE, "~~~~~~~~~~~~~~~~~~~~~~~~~Done~~~~~~~~~~~~~~~~~~~~~~~~~~")
      }
    }
  }
  
  /**
   * Get rpc method list for Android component
   * originally designed by Sankardas Roy, modified by Fengguo Wei
   */
  private def getRpcMethods(apk: ApkGlobal, comp: JawaClass, ra: ReachableInfoCollector): IMap[Signature, Boolean] = {
    val global = comp.global
    val methods = ra.getReachableMap.getOrElse(comp.getType, isetEmpty)
    val iinterface = global.getClassOrResolve(new JawaType("android.os.IInterface"))
    val iinterfaceImpls = global.getClassHierarchy.getAllImplementersOf(iinterface)
    val handler = global.getClassOrResolve(new JawaType("android.os.Handler"))
    val result: MMap[Signature, Boolean] = mmapEmpty
    methods.foreach { method =>
      val clazz = global.getClassOrResolve(method.classTyp)
      /* This is the remote service case. */
      if(iinterfaceImpls.contains(clazz)) {
        result ++= clazz.getMethods.filter(m => m.getDeclaringClass.isApplicationClass && !m.isConstructor && !m.isStatic).map(_.getSignature -> true)
      }
      /* This is the messenger service case. */
      if(global.getClassHierarchy.isClassRecursivelySubClassOf(clazz, handler)) {
        result ++= clazz.getMethod("handleMessage:(Landroid/os/Message;)V").map(_.getSignature -> true)
      }
    }
    /* This is the local service case. */
    result ++= comp.getDeclaredMethods.filter { method =>
      !(method.isConstructor || method.isStatic || AndroidEntryPointConstants.getServiceLifecycleMethods.contains(method.getSubSignature)
          || method.getName == AndroidConstants.MAINCOMP_ENV || method.getName == AndroidConstants.COMP_ENV)
    }.map(_.getSignature -> false)
    result.toMap
  }

  def collectInfo(apk: ApkGlobal, resolveCallBack: Boolean, guessAppPackages: Boolean = false): Unit = {
    apk.reporter.println(s"Collecting information from ${apk.model.getAppName}...")
    val certs = AppInfoCollector.readCertificates(apk.nameUri)
    val manifestUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "AndroidManifest.xml")
    val mfp = AppInfoCollector.analyzeManifest(apk.reporter, manifestUri)
    if(guessAppPackages) {
      apk.applyWhiteListPackages(GuessAppPackages.guess(mfp))
    }
    val afp = AppInfoCollector.analyzeARSC(apk.reporter, apk.nameUri)
    val lfp = AppInfoCollector.analyzeLayouts(apk, apk.model.layout.outputSrcUri, mfp, afp)
    apk.model.addCertificates(certs)
    apk.model.setPackageName(mfp.getPackageName)
    apk.model.addComponentInfos(mfp.getComponentInfos)
    apk.model.addUsesPermissions(mfp.getPermissions)
    apk.model.updateIntentFilterDB(mfp.getIntentDB)
    apk.model.addLayoutControls(lfp.getUserControls)
    val nativeActivity = apk.getClassOrResolve(new JawaType("android.app.NativeActivity"))
    mfp.getComponentInfos.foreach { f =>
      if(f.enabled){
        val comp = apk.getClassOrResolve(f.compType)
        if(f.typ == ComponentType.ACTIVITY && nativeActivity.isAssignableFrom(comp)) {
          apk.model.addNativeActivity(comp.getType)
        } else if(!comp.isUnknown && comp.isApplicationClass){
          apk.model.addComponent(comp.getType, f.typ)
        }
      }
    }
    if(resolveCallBack) {
      val ra = AppInfoCollector.reachabilityAnalysis(apk, mfp.getComponentInfos.map(_.compType))
      val callbacks = AppInfoCollector.analyzeCallback(apk.reporter, afp, lfp, ra)
      callbacks foreach {
        case (typ, sigs) => apk.model.addCallbackMethods(typ, sigs)
      }
      val asyncTask = apk.getClassOrResolve(new JawaType("android.os.AsyncTask"))
      ra.getReachableMap.flatMap(_._2).map(_.classTyp).filter { typ =>
        val clazz = apk.getClassOrResolve(typ)
        apk.getClassHierarchy.isClassRecursivelySubClassOf(clazz, asyncTask)
      }.foreach { typ =>
        generateAsyncTask(apk, typ)
      }

      apk.reporter.println(s"Generate environment for ${mfp.getComponentInfos.size} components.")
      mfp.getComponentInfos.foreach { f =>
        if(f.enabled){
          val comp = apk.getClassOrResolve(f.compType)
          if(!comp.isUnknown && comp.isApplicationClass){
            if(f.typ == ComponentType.SERVICE) {
              val rpcs = getRpcMethods(apk, comp, ra)
              apk.model.addRpcMethods(comp.getType, rpcs)
            }
            val clCounter = generateEnvironment(apk, comp, if(f.exported)AndroidConstants.MAINCOMP_ENV else AndroidConstants.COMP_ENV)
            apk.model.setCodeLineCounter(clCounter)
          }
        }
      }
    }

    apk.reporter.println("Info collection done.")
  }
}
