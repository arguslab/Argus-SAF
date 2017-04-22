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

import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.pta.PTAScopeManager
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCallHandler
import org.argus.jawa.core.{JawaType, Signature}

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
    (apk.getClassHierarchy.isClassRecursivelySubClassOfIncluding(calleeSig.getClassType, new JawaType("android.os.Messenger"))
      && calleeSig.getSubSignature == "send:(Landroid/os/Message;)V") || apk.model.getRpcMethodMapping.exists{ case (typ, sigs) => currentComp != typ && sigs.contains(calleeSig)}
  }

}
