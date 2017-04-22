/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.pilarCodeGenerator

import org.argus.jawa.core.{Global, JawaClass, JawaType, Signature}
import org.argus.jawa.core.pilarCodeGenerator.MethodGenerator
import org.argus.jawa.core.util._

/**
  * Created by fgwei on 4/22/17.
  */
class AsyncTaskEnvGenerator(global: Global) extends MethodGenerator(global) {
  override def generateInternal(methods: List[Signature]): String = {
    val classFragment = new CodeFragmentGenerator
    classFragment.addLabel()
    codeFragments.add(classFragment)
    val clazz = global.getClassOrResolve(this.currentComponent)
    asyncTaskLifeCycleGenerator(mlistEmpty, clazz, classFragment)
    localVarsTemplate.add("locals", localVars)
    bodyTemplate.add("codeFragments", generateBody())
    procDeclTemplate.add("localVars", localVarsTemplate.render())
    procDeclTemplate.add("body", bodyTemplate.render())
    procDeclTemplate.render()
  }

  private def asyncTaskLifeCycleGenerator(entryPoints: MList[Signature], clazz: JawaClass, classFragment: CodeFragmentGenerator) = {
    val constructionStack: MSet[JawaType] = msetEmpty ++ this.paramClasses
    // 1. onPreExecute:
    searchAndBuildMethodCall(AndroidEntryPointConstants.ASYNCTASK_ONPREEXECUTE, clazz, entryPoints, constructionStack, classFragment)
    // 2. doInBackground:
    searchAndBuildMethodCall(AndroidEntryPointConstants.ASYNCTASK_DOINBACKGROUND, clazz, entryPoints, constructionStack, classFragment)
    // 3. onProgressUpdate:
    searchAndBuildMethodCall(AndroidEntryPointConstants.ASYNCTASK_ONPROGRESSUPDATE, clazz, entryPoints, constructionStack, classFragment)
    // 4. onPostExecute:
    searchAndBuildMethodCall(AndroidEntryPointConstants.ASYNCTASK_ONPOSTEXECUTE, clazz, entryPoints, constructionStack, classFragment)
  }
}
