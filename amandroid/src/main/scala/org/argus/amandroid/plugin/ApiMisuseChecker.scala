/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.util.IMap
import org.argus.jawa.core.Global

object ApiMisuseModules extends Enumeration {
  val CRYPTO_MISUSE, HIDE_ICON, SSLTLS_MISUSE = Value
}

trait ApiMisuseChecker {
  def name: String
  def check(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): ApiMisuseResult
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
