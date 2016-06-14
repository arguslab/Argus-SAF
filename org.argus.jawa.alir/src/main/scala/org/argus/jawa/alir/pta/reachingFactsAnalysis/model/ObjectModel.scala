/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.{ClassInstance, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.{JawaClass, JawaMethod}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ObjectModel {
  val TITLE = "ObjectModel"
  def isObject(r: JawaClass): Boolean = r.getName == "java.lang.Object"
    
  def doObjectCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Ljava/lang/Object;.<init>:()V" =>
        byPassFlag = false
      case "Ljava/lang/Object;.getClass:()Ljava/lang/Class;" =>
        require(retVars.size == 1)
        objectGetClass(s, args, retVars.head, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  private def objectGetClass(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      cIns =>
        val typ = cIns.typ
        val strIns = ClassInstance(typ, cIns.defSite)
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), strIns)
    }
    (newfacts, delfacts)
  }
  
  
}
