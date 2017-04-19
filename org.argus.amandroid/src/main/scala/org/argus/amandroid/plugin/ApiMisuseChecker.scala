/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.core.util.IMap
import org.argus.jawa.core.Global

object ApiMisuseModules extends Enumeration {
  val CRYPTO_MISUSE, HIDE_ICON, SSLTLS_MISUSE = Value
}

trait ApiMisuseChecker {
  def name: String
  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult
}

case class ApiMisuseResult(checkerName: String, misusedApis: IMap[(String, String), String]) {
  override def toString: String = {
    val sb = new StringBuilder
    sb.append(checkerName + ":\n")
    if(misusedApis.isEmpty) sb.append("  No misuse.\n")
    misusedApis.foreach {
      case ((sig, line), des) => sb.append("  " + sig + " " + line + " : " + des + "\n")
    }
    sb.toString().intern()
  }
}
