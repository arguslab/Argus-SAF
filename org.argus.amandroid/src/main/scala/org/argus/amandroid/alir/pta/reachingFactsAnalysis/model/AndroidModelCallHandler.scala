/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.pta.PTAScopeManager
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.{ModelCall, ModelCallHandler}
import org.argus.jawa.core.{JawaMethod, JawaType, Signature}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidModelCallHandler extends ModelCallHandler(PTAScopeManager){

  registerModelCall(new BundleModel)
  registerModelCall(new ComponentNameModel)
  registerModelCall(new IntentFilterModel)
  registerModelCall(new IntentModel)
  registerModelCall(new UriModel)
  registerModelCall(new ActivityModel)
  registerModelCall(new ContextModel)
  
  def isICCCall(calleeSig: Signature): Boolean = {
    InterComponentCommunicationModel.isIccOperation(calleeSig)
  }

  def isRPCCall(apk: ApkGlobal, currentComp: JawaType, calleeSig: Signature): Boolean = {
    val messenger = apk.getClassOrResolve(new JawaType("android.os.Messenger"))
    val clazz = apk.getClassOrResolve(calleeSig.getClassType)
    (apk.getClassHierarchy.isClassRecursivelySubClassOfIncluding(clazz, messenger)
      && calleeSig.getSubSignature == "send:(Landroid/os/Message;)V") || apk.model.getRpcMethodMapping.exists{ case (typ, sigs) => currentComp != typ && sigs.contains(calleeSig)}
  }

}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class BundleModel extends ModelCall {
  def safsuFile = "Bundle.safsu"
  def isModelCall(r: JawaMethod): Boolean = r.getDeclaringClass.getName.equals(AndroidConstants.BUNDLE)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class ComponentNameModel extends ModelCall {
  def safsuFile: String = "ComponentName.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("android.content.ComponentName")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class UriModel extends ModelCall {
  def safsuFile: String = "Uri.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("android.net.Uri")
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class ActivityModel extends ModelCall {
  def safsuFile: String = "Activity.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(AndroidConstants.ACTIVITY)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class IntentModel extends ModelCall {
  def safsuFile: String = "Intent.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(AndroidConstants.INTENT)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class IntentFilterModel extends ModelCall {
  def safsuFile: String = "IntentFilter.safsu"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(AndroidConstants.INTENT_FILTER)
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
  */
class ContextModel extends ModelCall {
  def safsuFile: String = "Context.safsu"
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val contextRec = p.getDeclaringClass.global.getClassOrResolve(new JawaType("android.content.Context"))
      p.getDeclaringClass.global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(p.getDeclaringClass, contextRec)
    }
  }
}