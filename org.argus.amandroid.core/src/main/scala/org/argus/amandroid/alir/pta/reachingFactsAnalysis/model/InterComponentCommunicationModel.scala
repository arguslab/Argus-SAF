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

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.{PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JawaMethod, Signature}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object InterComponentCommunicationModel {
  final val TITLE = "InterComponentCommunicationModel"
  def isIccOperation(proc: Signature): Boolean = {
    var flag = false
    AndroidConstants.getIccMethods.foreach{
      item =>
        if(proc.getSubSignature == item)
         flag = true
    }
    flag
  }

//  def doIccCall(apk: ApkGlobal, s: PTAResult, calleeSig: Signature, args: List[String], retVars: Seq[String], currentContext: Context): (ISet[RFAFact], ISet[JawaMethod]) = {
//    require(args.size > 1)
//    val intentSlot = VarSlot(args(1), isBase = false, isArg = true)
//    val intentValues = s.pointsToSet(intentSlot, currentContext)
//    val intentcontents = IntentHelper.getIntentContents(s, intentValues, currentContext)
//    val compType: AndroidConstants.CompType.Value = AndroidConstants.getIccCallType(calleeSig.getSubSignature)
//    val comMap = IntentHelper.mappingIntents(apk, intentcontents, compType)
//    val targets: MSet[JawaMethod] = msetEmpty
//    comMap.foreach{
//      case (_, comTypes) =>
//        comTypes.foreach{
//          case (comType, _) =>
//            val com = apk.getClassOrResolve(comType)
//            com.getMethod(AndroidConstants.MAINCOMP_ENV_SUBSIG) match{
//              case Some(r) => targets += r
//              case None =>
//                com.getMethod(AndroidConstants.COMP_ENV_SUBSIG) match{
//                  case Some(r) => targets += r
//                  case None =>
//                }
//            }
//        }
//    }
//    (isetEmpty, targets.toSet)
//  }

}
