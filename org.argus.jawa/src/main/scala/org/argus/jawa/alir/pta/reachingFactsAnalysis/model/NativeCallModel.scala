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
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.core.{Constants, JawaMethod}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class NativeCallModel extends ModelCall {
   def isModelCall(p: JawaMethod): Boolean = p.isNative
   
   def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
        
    p.getSignature.signature match{
      case "Ljava/lang/Object;.getClass:()Ljava/lang/Class;" =>
        // algo:thisvalue.foreach {ins => set insRec's classObj field with a classIns whose type is java:lang:Class and name is same as ins's type
                 // then, create two facts (a) (retVarSlot, insRec.classObj), (b) ([insRec.classObj, "java:lang:Class.name"], concreteString(ins.typ))}
        require(args.nonEmpty)
        val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
        val thisValue = s.pointsToSet(thisSlot, currentContext)
        thisValue.foreach{
          ins =>
            val insClasObj = ClassInstance(ins.typ, currentContext)
            newFacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), insClasObj)
            val strIns = PTAConcreteStringInstance(insClasObj.getName, insClasObj.defSite)
            newFacts += new RFAFact(FieldSlot(insClasObj, Constants.CLASS_NAME), strIns)
        }
        byPassFlag = false
      case "Ljava/lang/Class;.getNameNative:()Ljava/lang/String;" =>
        // algo:thisValue.foreach.{ cIns => get value of (cIns.name") and create fact (retVar, value)}
        require(args.nonEmpty)
        val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
        val thisValue = s.pointsToSet(thisSlot, currentContext)
        thisValue.foreach{
          cIns =>
            println(cIns + " " + cIns.getClass)
            require(cIns.isInstanceOf[ClassInstance])
            val name = cIns.asInstanceOf[ClassInstance].getName
            val strIns = PTAConcreteStringInstance(name, cIns.defSite)
              newFacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), strIns)
        }
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
}
