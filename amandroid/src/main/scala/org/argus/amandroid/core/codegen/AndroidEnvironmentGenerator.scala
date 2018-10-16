/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.codegen

import org.argus.jawa.core.util._
import org.argus.amandroid.core.parser.{ComponentInfo, ComponentType}
import org.argus.jawa.core._
import org.argus.jawa.core.codegen.MethodGenerator
import org.argus.jawa.core.elements.{JawaType, Signature}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidEnvironmentGenerator(global: Global) extends MethodGenerator(global) {
  private var componentInfos: Set[ComponentInfo] = Set()
  
  def setComponentInfos(componentInfos: Set[ComponentInfo]): Unit = this.componentInfos = componentInfos
  
  def generateInternal(methods: List[Signature]): String = {
    val classMap: MMap[JawaType, MList[Signature]] = mmapEmpty
    methods.foreach { method =>
      val clazz = method.getClassType
      classMap.getOrElseUpdate(clazz, mlistEmpty) += method
    }
    if(!classMap.contains(this.currentComponent)) classMap.getOrElseUpdate(this.currentComponent, mlistEmpty)
//    val intVar = template.getInstanceOf("LocalVar")
    val outerStartFragment = new CodeFragmentGenerator
    outerStartFragment.addLabel()
    codeFragments.add(outerStartFragment)
    classMap.foreach{ item =>
      val classStartFragment = new CodeFragmentGenerator
      classStartFragment.addLabel()
      codeFragments.add(classStartFragment)
      val entryExitFragment = new CodeFragmentGenerator
      createIfStmt(entryExitFragment, classStartFragment)
      val endClassFragment = new CodeFragmentGenerator
      try{
        var activity = false
        var service = false
        var broadcastReceiver = false
        var contentProvider = false
        var plain = false
        val currentClass = global.getClassOrResolve(item._1)
        val ancestors = global.getClassHierarchy.getAllSuperClassesOfIncluding(currentClass)
        ancestors.foreach{ ancestor =>
          val recName = ancestor.getName
          if(recName.equals(AndroidEntryPointConstants.ACTIVITY_CLASS)) activity = true
          if(recName.equals(AndroidEntryPointConstants.SERVICE_CLASS)) service = true
          if(recName.equals(AndroidEntryPointConstants.BROADCAST_RECEIVER_CLASS)) broadcastReceiver = true
          if(recName.equals(AndroidEntryPointConstants.CONTENT_PROVIDER_CLASS)) contentProvider = true
        }
        componentInfos.foreach{ ci =>
          if(ci.compType.name == currentClass.getName){
            ci.typ match{
              case ComponentType.ACTIVITY => activity = true
              case ComponentType.SERVICE => service = true
              case ComponentType.RECEIVER => broadcastReceiver = true
              case ComponentType.PROVIDER => contentProvider = true
            }
          }
        }
        if(!activity && !service && !broadcastReceiver && !contentProvider) plain = true
        var instanceNeeded = activity || service || broadcastReceiver || contentProvider
        //How this part work? item._2 always empty!
        var plainMethods: Map[Signature, JawaMethod] = Map()
        if(!instanceNeeded || plain) {
          item._2.foreach{
            procSig =>
              global.getMethod(procSig) match {
                case Some(p) =>
                  plainMethods += (procSig -> p)
                  if(!p.isStatic) instanceNeeded = true
                case None =>
              }
          }
        }
        if(instanceNeeded){
          val va = generateInstanceCreation(currentClass.getType, classStartFragment)
          this.localVarsForClasses += (currentClass.getType -> va)
          generateClassConstructor(currentClass, msetEmpty, classStartFragment)
        }
        val classLocalVar = localVarsForClasses.getOrElse(currentClass.getType, null)

        //now start to generate lifecycle for the four kinds of component
        if(activity){
          activityLifeCycleGenerator(item._2, currentClass, endClassFragment, classLocalVar, classStartFragment)
        }
        if(service){
          serviceLifeCycleGenerator(item._2, currentClass, endClassFragment, classLocalVar, classStartFragment)
        }
        if(broadcastReceiver){
          broadcastReceiverLifeCycleGenerator(item._2, currentClass, endClassFragment, classLocalVar, classStartFragment)
        }
        if(contentProvider){
          contentProviderLifeCycleGenerator(item._2, currentClass, endClassFragment, classLocalVar, classStartFragment)
        }
        if(plain){
          plainClassGenerator(plainMethods, endClassFragment, classLocalVar, classStartFragment)
        }
      } finally {
        endClassFragment.addLabel()
        codeFragments.add(endClassFragment)
        entryExitFragment.addLabel()
        codeFragments.add(entryExitFragment)
      }
    }
    val outerExitFragment = new CodeFragmentGenerator
    outerExitFragment.addLabel()
    createIfStmt(outerStartFragment, outerExitFragment)
    createReturnStmt("@void", outerExitFragment)
    codeFragments.add(outerExitFragment)
    localVarsTemplate.add("locals", localVars)
    bodyTemplate.add("codeFragments", generateBody())
    procDeclTemplate.add("localVars", localVarsTemplate.render())
    procDeclTemplate.add("body", bodyTemplate.render())
    procDeclTemplate.render()
  }



  /**
   * Generate plain class methods calling sequence. Because we don't know
   * the order of the custom statements, we assume that it can loop arbitrarily.
   * 
   */
  private def plainClassGenerator(plainMethods: Map[Signature, JawaMethod], endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator): Unit = {
    val beforeClassFragment = new CodeFragmentGenerator
    beforeClassFragment.addLabel()
    codeFragments.add(beforeClassFragment)
    plainMethods.foreach{
      case (currentMethodSig, currentMethod) =>
        if(currentMethod.isStatic || classLocalVar != null){
          val ifFragment = new CodeFragmentGenerator
          val thenFragment = new CodeFragmentGenerator
          ifFragment.addLabel()
          codeFragments.add(ifFragment)
          createIfStmt(thenFragment, ifFragment)
          val elseFragment = new CodeFragmentGenerator
          val elseGotoFragment = new CodeFragmentGenerator
          elseGotoFragment.addLabel()
          createGotoStmt(elseFragment, elseGotoFragment)
          codeFragments.add(elseGotoFragment)
          thenFragment.addLabel()
          codeFragments.add(thenFragment)
          generateMethodCall(currentMethodSig, "virtual", classLocalVar, msetEmpty, thenFragment)
          createIfStmt(endClassFragment, thenFragment)
          elseFragment.addLabel()
          codeFragments.add(elseFragment)
          createIfStmt(beforeClassFragment, elseFragment)
        } else {
//          err_msg_normal(TITLE, "Skipping method " + currentMethod + " because we have no instance")
        }
    }
  }

//  private def asyncTaskLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator) = {
////    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
//    createIfStmt(endClassFragment, codefg)
//  }

  private def contentProviderLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator) = {
    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
    createIfStmt(endClassFragment, codefg)
  
    // 1. onCreate:
    val onCreateFragment = new CodeFragmentGenerator
    onCreateFragment.addLabel()
    codeFragments.add(onCreateFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.CONTENTPROVIDER_ONCREATE, clazz, entryPoints, constructionStack, onCreateFragment)
    
    //all other entry points of this class can be called in arbitary order
    val endWhileFragment = generateAllCallbacks(entryPoints, clazz, classLocalVar)
    createIfStmt(onCreateFragment, endWhileFragment)
  }

  private def broadcastReceiverLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator) = {
    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
    createIfStmt(endClassFragment, codefg)
  
    // 1. onReceive:
    val onReceiveFragment = new CodeFragmentGenerator
    onReceiveFragment.addLabel()
    codeFragments.add(onReceiveFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.BROADCAST_ONRECEIVE, clazz, entryPoints, constructionStack, onReceiveFragment)
    
    //all other entry points of this class can be called in arbitary order
    val endWhileFragment = generateAllCallbacks(entryPoints, clazz, classLocalVar)
    createIfStmt(onReceiveFragment, endWhileFragment)
  }

  private def serviceLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator) = {
    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
    createIfStmt(endClassFragment, codefg)

    val r = global.getClassOrResolve(new JawaType("android.app.ContextImpl"))
    val va = generateInstanceCreation(r.getType, codefg)
    localVarsForClasses += (r.getType -> va)
    generateClassConstructor(r, constructionStack, codefg)
    createFieldSetStmt(localVarsForClasses(clazz.getType), "android.content.ContextWrapper.mBase", va, "object", new JawaType("android.content.Context"), codefg)
  
  
    // 1. onCreate:
    val onCreateFragment = new CodeFragmentGenerator
    onCreateFragment.addLabel()
    codeFragments.add(onCreateFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONCREATE, clazz, entryPoints, constructionStack, onCreateFragment)
    // service has two different lifecycles:
    // lifecycle 1:
    // 2. onStart:
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONSTART1, clazz, entryPoints, constructionStack, onCreateFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONSTART2, clazz, entryPoints, constructionStack, onCreateFragment)
    //all other entry points of this class can be called in arbitary order
//    generateAllCallbacks(entryPoints, clazz, classLocalVar)
    // lifecycle 1 end.
  
    // lifecycle 2:
    // 2. onBind:
    val onBindFragment = new CodeFragmentGenerator
    onBindFragment.addLabel()
    codeFragments.add(onBindFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONBIND, clazz, entryPoints, constructionStack, onBindFragment)
    val beforemethodsFragment = new CodeFragmentGenerator
    beforemethodsFragment.addLabel()
    codeFragments.add(beforemethodsFragment)
    //all other entry points of this class can be called in arbitary order
    generateAllCallbacks(entryPoints, clazz, classLocalVar)
  
    // 3. onRebind:
    val onRebindFragment = new CodeFragmentGenerator
    onRebindFragment.addLabel()
    codeFragments.add(onRebindFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONREBIND, clazz, entryPoints, constructionStack, onRebindFragment)
    createIfStmt(beforemethodsFragment, onRebindFragment)
    
    // 4. onUnbind:
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONUNBIND, clazz, entryPoints, constructionStack, onRebindFragment)
    createIfStmt(onBindFragment, onRebindFragment)
    // lifecycle 2 end.
    
    // 3 | 5. onDestroy:
    val onDestroyFragment = new CodeFragmentGenerator
    onDestroyFragment.addLabel()
    codeFragments.add(onDestroyFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.SERVICE_ONDESTROY, clazz, entryPoints, constructionStack, onDestroyFragment)
    // either begin or end or next class:
    createIfStmt(onCreateFragment, onDestroyFragment)
    createIfStmt(endClassFragment, onDestroyFragment)
  }

  private def activityLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, endClassFragment: CodeFragmentGenerator, classLocalVar: String, codefg: CodeFragmentGenerator) = {
    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
    createIfStmt(endClassFragment, codefg)
    val r = global.getClassOrResolve(new JawaType("android.app.ContextImpl"))
    val va = generateInstanceCreation(r.getType, codefg)
    localVarsForClasses += (r.getType -> va)
    generateClassConstructor(r, constructionStack, codefg)
    createFieldSetStmt(localVarsForClasses(clazz.getType), "android.view.ContextThemeWrapper.mBase", va, "object", new JawaType("android.content.Context"), codefg)
    
    generateMethodCall(AndroidEntryPointConstants.ACTIVITY_SETINTENT_SIG, "virtual", localVarsForClasses(clazz.getType), constructionStack, codefg)
  
    // 1. onCreate:
    val onCreateFragment = new CodeFragmentGenerator
    onCreateFragment.addLabel()
    codeFragments.add(onCreateFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONCREATE, clazz, entryPoints, constructionStack, onCreateFragment)
    // 2. onStart:
    val onStartFragment = new CodeFragmentGenerator
    onStartFragment.addLabel()
    codeFragments.add(onStartFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONSTART, clazz, entryPoints, constructionStack, onStartFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONRESTOREINSTANCESTATE, clazz, entryPoints, constructionStack, onStartFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONPOSTCREATE, clazz, entryPoints, constructionStack, onStartFragment)
    // 3. onResume:
    val onResumeFragment = new CodeFragmentGenerator
    onResumeFragment.addLabel()
    codeFragments.add(onResumeFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONRESUME, clazz, entryPoints, constructionStack, onResumeFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONPOSTRESUME, clazz, entryPoints, constructionStack, onResumeFragment)
  
    // all other entry points of this activity
    generateAllCallbacks(entryPoints, clazz, classLocalVar)
    // 4. onPause:
    val onPauseFragment = new CodeFragmentGenerator
    onPauseFragment.addLabel()
    codeFragments.add(onPauseFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONPAUSE, clazz, entryPoints, constructionStack, onPauseFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONCREATEDESCRIPTION, clazz, entryPoints, constructionStack, onPauseFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONSAVEINSTANCESTATE, clazz, entryPoints, constructionStack, onPauseFragment)
    // goto onDestroy, onRestart or onCreate:
    val onStopFragment = new CodeFragmentGenerator
    createIfStmt(onStopFragment, onPauseFragment)
    createIfStmt(onResumeFragment, onPauseFragment)
    createIfStmt(onCreateFragment, onPauseFragment)
  
    // 5. onStop:
    onStopFragment.addLabel()
    codeFragments.add(onStopFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONSTOP, clazz, entryPoints, constructionStack, onStopFragment)
    //goto onDestroy, onRestart or onCreate:
    val onDestroyFragment = new CodeFragmentGenerator
    val onRestartFragment = new CodeFragmentGenerator
    createIfStmt(onDestroyFragment, onStopFragment)
    createIfStmt(onRestartFragment, onStopFragment)
    createIfStmt(onCreateFragment, onStopFragment)
    
    // 6. onRestart:
    onRestartFragment.addLabel()
    codeFragments.add(onRestartFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONRESTART, clazz, entryPoints, constructionStack, onRestartFragment)
    if(onStartFragment != null){
      createGotoStmt(onStartFragment, onRestartFragment)
    }
    
    // 7. onDestroy:
    onDestroyFragment.addLabel()
    codeFragments.add(onDestroyFragment)
    searchAndBuildMethodCall(AndroidEntryPointConstants.ACTIVITY_ONDESTROY, clazz, entryPoints, constructionStack, onDestroyFragment)
    
    createIfStmt(endClassFragment, onDestroyFragment)
  }

  private def generateAllCallbacks(entryPoints: MList[Signature], clazz: JawaClass, classLocalVar: String): CodeFragmentGenerator = {
    val startWhileFragment = new CodeFragmentGenerator
    startWhileFragment.addLabel()
    codeFragments.add(startWhileFragment)
    val endWhileFragment = new CodeFragmentGenerator
    val methods = clazz.getDeclaredMethods
    for(currentMethod <- methods){
      if(entryPoints.contains(currentMethod.getSignature)){ 
        val pSig = currentMethod.getSignature
        if(!AndroidEntryPointConstants.getActivityLifecycleMethods.contains(currentMethod.getSubSignature)){
          val thenStmtFragment = new CodeFragmentGenerator
          createIfStmt(thenStmtFragment, startWhileFragment)
          val elseStmtFragment = new CodeFragmentGenerator
          createGotoStmt(elseStmtFragment, startWhileFragment)
          thenStmtFragment.addLabel()
          codeFragments.add(thenStmtFragment)
          generateMethodCall(pSig, "virtual", classLocalVar, msetEmpty + clazz.getType, thenStmtFragment)
          elseStmtFragment.addLabel()
          codeFragments.add(elseStmtFragment)
        }
      }
    }
    val callBackFragment = new CodeFragmentGenerator
    callBackFragment.addLabel()
    codeFragments.add(callBackFragment)
    addCallbackMethods(clazz, classLocalVar, callBackFragment)
    endWhileFragment.addLabel()
    codeFragments.add(endWhileFragment)
    createIfStmt(startWhileFragment, endWhileFragment)
    endWhileFragment
  }

}
