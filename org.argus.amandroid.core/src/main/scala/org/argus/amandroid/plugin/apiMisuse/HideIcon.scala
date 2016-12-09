/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.apiMisuse

import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult}
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.core.util.ASTUtil
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author Kaushik Nmmala
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class HideIcon extends ApiMisuseChecker {

  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val result: MMap[(Signature, String), String] = mmapEmpty
    global.getApplicationClasses foreach {
      ac =>
        ac.getDeclaredMethods foreach {
          method =>
            if(hasHideIconAPI(method)) result((method.getSignature, "")) = "Hide app icon."
        }
    }
    ApiMisuseResult(result.toMap)
  }

  private def hasHideIconAPI(method: JawaMethod): Boolean = {
    var result:Boolean = false
    method.getBody.locations foreach {
      case jumpLoc: JumpLocation =>
        jumpLoc.jump match {
          case t: CallJump if t.jump.isEmpty =>
            ASTUtil.getSignature(t) match {
              case Some(signature) =>
                if (signature.getSubSignature == "setComponentEnabledSetting:(Landroid/content/ComponentName;II)V") {
                  val valuesForParam2 = ExplicitValueFinder.findExplicitIntValueForArgs(method, jumpLoc, 2)
                  if (valuesForParam2.contains(2)) {
                    val valuesForParam3 = ExplicitValueFinder.findExplicitIntValueForArgs(method, jumpLoc, 3)
                    if (valuesForParam3.contains(1)) {
                      result = true
                    }
                  }
                }
              case None =>
            }

          case _ =>
        }

      case _ =>
    }
    result
  }
}
