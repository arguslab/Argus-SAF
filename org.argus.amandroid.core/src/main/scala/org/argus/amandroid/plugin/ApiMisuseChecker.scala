/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin

import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.sireum.util.IMap
import org.argus.jawa.core.{Global, Signature}

object ApiMisuseModules extends Enumeration {
  val CRYPTO_MISUSE, HIDE_ICON = Value
}

trait ApiMisuseChecker {
  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult
}

case class ApiMisuseResult(misusedApis: IMap[(Signature, String), String]) {
  def print(): Unit = misusedApis.foreach {
    case ((sig, line), des) => println(sig + " " + line + " : " + des)
  }
}
