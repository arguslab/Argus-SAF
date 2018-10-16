/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.oauth

import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.ast.{AssignmentStatement, LiteralExpression, Location}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class OAuthSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){

  override def isStmtSource(apk: ApkGlobal, loc: Location): Boolean = {
    var flag = false
    val visitor = Visitor.build({
      case as: AssignmentStatement =>
        as.rhs match {
          case le: LiteralExpression =>
            if(le.isString){
              if(le.getString.contains("content://call_log/calls"))
                flag = true
            }
            false
          case _ =>
            false
        }
    })
    visitor(loc)
    flag
  }
}
