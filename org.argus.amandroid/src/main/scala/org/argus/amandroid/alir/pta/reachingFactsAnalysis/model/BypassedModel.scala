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

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.util._

object BypassedModel {
  def handleBypass(s: PTAResult, calleeMethod: JawaMethod, args: List[String], retVar: String, currentContext: Context): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    (isetEmpty, isetEmpty, true)
  }
}
