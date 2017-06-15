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
import org.argus.jawa.alir.pta.{ClassInstance, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class ObjectModel extends ModelCall {
  val TITLE = "ObjectModel"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.Object")
    
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Ljava/lang/Object;.<init>:()V" =>
        byPassFlag = false
      case "Ljava/lang/Object;.getClass:()Ljava/lang/Class;" =>
        objectGetClass(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  private def objectGetClass(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head)
    val thisValue = s.pointsToSet(after = false, currentContext, thisSlot)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{ cIns =>
      val typ = cIns.typ
      val strIns = ClassInstance(typ, cIns.defSite)
      newfacts += new RFAFact(VarSlot(retVar), strIns)
    }
    (newfacts, delfacts)
  }
  
  
}
