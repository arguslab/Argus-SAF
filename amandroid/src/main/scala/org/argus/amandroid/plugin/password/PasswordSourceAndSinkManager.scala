/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.password

import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.argus.jawa.core.ast.{CallStatement, Location}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.Signature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class PasswordSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){
  private final val TITLE = "PasswordSourceAndSinkManager"
  
  override def isUISource(apk: ApkGlobal, calleeSig: Signature, callerSig: Signature, callerLoc: Location): Boolean = {
    if(calleeSig.signature == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig.signature == AndroidConstants.VIEW_FINDVIEWBYID){
      val callerMethod = apk.getMethod(callerSig).get
      val cs = callerLoc.statement.asInstanceOf[CallStatement]
      val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerMethod, callerLoc, cs.arg(0))
      nums.filter(_.isInt).foreach{ num =>
        apk.model.getLayoutControls.get(num.getInt) match{
          case Some(control) =>
            return control.isSensitive
          case None =>
            apk.reporter.error(TITLE, "Layout control with ID " + num + " not found.")
        }
      }
    }
    false
  }
}
