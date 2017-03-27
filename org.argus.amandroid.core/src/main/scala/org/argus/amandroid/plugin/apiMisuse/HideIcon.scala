/*
 * Copyright (c) 2017. Fengguo Wei and others.
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
import org.argus.jawa.core.{Global, JawaMethod}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author Kaushik Nmmala
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class HideIcon extends ApiMisuseChecker {

  val name = "HideIcon"

  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val result: MMap[(String, String), String] = mmapEmpty
    global.getApplicationClassCodes foreach { case (typ, file) =>
      if(file.code.contains("setComponentEnabledSetting:(Landroid/content/ComponentName;II)V")) {
        val clazz = global.getClassOrResolve(typ)
        clazz.getDeclaredMethods foreach { method =>
          hasHideIconAPI(method) match {
            case Some(loc) => result((method.getSignature.signature, loc)) = "Hide app icon."
            case None =>
          }
        }
      }
    }
    ApiMisuseResult(name, result.toMap)
  }

  private def hasHideIconAPI(method: JawaMethod): Option[String] = {
    var result: Option[String] = None
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
                      result = jumpLoc.name.map(_.name)
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
