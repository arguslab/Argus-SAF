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
import org.argus.jawa.compiler.parser.CallStatement
import org.argus.jawa.core.{Global, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author Kaushik Nmmala
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class HideIcon(mainActivity: JawaType) extends ApiMisuseChecker {

  val name = "HideIcon"

  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val result: MMap[(String, String), String] = mmapEmpty
    val clazz = global.getClassOrResolve(mainActivity)
    if(!clazz.isSystemLibraryClass && clazz.isConcrete) {
      clazz.getDeclaredMethods foreach { method =>
        val code = method.getBody.toCode
        if (code.contains("setComponentEnabledSetting:(Landroid/content/ComponentName;II)V")) {
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
    method.getBody.resolvedBody.locations.foreach{ l =>
      l.statement match {
        case cs: CallStatement =>
          if (cs.signature.getSubSignature == "setComponentEnabledSetting:(Landroid/content/ComponentName;II)V") {
            val valuesForParam2 = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(1))
            if (valuesForParam2.filter(_.isInt).map(_.getInt).contains(2)) {
              val valuesForParam3 = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(2))
              if (valuesForParam3.filter(_.isInt).map(_.getInt).contains(1)) {
                result = Some(l.locationUri)
              }
            }
          }
        case _ =>
      }
    }
    result
  }
}
