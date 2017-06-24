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
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.alir.pta.{PTAResult, PTAScopeManager}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.{ModelCall, ModelCallHandler}
import org.argus.jawa.core.util.{ISet, isetEmpty}
import org.argus.jawa.core.{JawaMethod, JawaType, Signature}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidModelCallHandler extends ModelCallHandler(PTAScopeManager){

  registerModelCall(new BundleModel)
  registerModelCall(new HandlerModel)
  registerModelCall(new ComponentNameModel)
  registerModelCall(new IntentFilterModel)
  registerModelCall(new IntentModel)
  registerModelCall(new UriModel)
  registerModelCall(new FrameworkMethodsModel)
  registerModelCall(new ActivityModel)
  
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
  def isModelCall(r: JawaMethod): Boolean = r.getDeclaringClass.getName.equals(AndroidConstants.BUNDLE)

  override val safsuFile = "Bundle.safsu"

  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    (isetEmpty, isetEmpty, true)
  }
}
