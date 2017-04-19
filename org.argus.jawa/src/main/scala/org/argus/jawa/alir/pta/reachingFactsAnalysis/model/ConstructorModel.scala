/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JawaMethod, ScopeManager}
import org.argus.jawa.core.util._

object ConstructorModel {
  val TITLE = "ConstructorModel"
  def isConstructor(m: JawaMethod): Boolean = {
    val res = ScopeManager.getCurrentScopeManager.shouldBypass(m.getDeclaringClass) &&
      m.getName.contains(m.getDeclaringClass.constructorName)
    res
  }
  
  def doConstructorCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    val newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    val byPassFlag = true
    (newFacts, delFacts, byPassFlag)
  }
}
