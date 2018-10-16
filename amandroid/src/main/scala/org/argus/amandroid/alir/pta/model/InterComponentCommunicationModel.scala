/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.model

import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.parser.{IntentFilter, IntentFilterDataBase}
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.flow.pta.{FieldSlot, PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.{ISet, MSet, isetEmpty, msetEmpty}


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object InterComponentCommunicationModel {
  def isIccOperation(proc: Signature): Boolean = {
    AndroidConstants.getIccMethods.foreach{ item =>
      if(proc.getSubSignature == item) {
        return true
      }
    }
    false
  }

  def isRegisterReceiver(sig: Signature): Boolean = {
    sig.getSubSignature == "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;" ||
    sig.getSubSignature == "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;"
  }

  def registerReceiver(apk: ApkGlobal, s: PTAResult, recvOpt: Option[String], args: List[String], currentContext: Context): ISet[RFAFact] ={
    require(args.size >= 2)
    val receiverSlot = VarSlot(args.head)
    val receiverValue = s.pointsToSet(currentContext, receiverSlot)
    val filterSlot = VarSlot(args(1))
    val filterValue = s.pointsToSet(currentContext, filterSlot)
    val permissionSlotOpt =
      if(args.lift(2).isDefined) Some(VarSlot(args(2)))
      else None
    val permissionValueOpt =
      if(permissionSlotOpt.isDefined) Some(s.pointsToSet(currentContext, permissionSlotOpt.get))
      else None
    val iDB = new IntentFilterDataBase
    receiverValue.foreach {
      case ui if ui.isUnknown =>
      case rv =>
        val intentF = new IntentFilter(rv.typ)
        val comRec = apk.getClassOrResolve(rv.typ)
        filterValue.foreach { fv =>
          val mActionsSlot = FieldSlot(fv, AndroidConstants.INTENT_FILTER_ACTIONS)
          val mActionsValue = s.pointsToSet(currentContext, mActionsSlot)
          mActionsValue.foreach {
            case PTAConcreteStringInstance(text, _) =>
              intentF.addAction(text)
            case _ =>
              intentF.addAction("ANY")
          }
          val mCategoriesSlot = FieldSlot(fv, AndroidConstants.INTENT_FILTER_CATEGORIES)
          val mCategoriesValue = s.pointsToSet(currentContext, mCategoriesSlot)
          mCategoriesValue.foreach {
            case PTAConcreteStringInstance(text, _) =>
              intentF.addCategory(text)
            case _ =>
              intentF.addCategory("ANY")
          }
        }
        val permission: MSet[String] = msetEmpty
        permissionValueOpt.foreach { pvs =>
          pvs foreach {
            case PTAConcreteStringInstance(text, _) =>
              permission += text
            case _ =>
          }
        }
        iDB.updateIntentFmap(intentF)
        if (!apk.model.hasEnv(rv.typ)) {
          AppInfoCollector.dynamicRegisterReceiver(apk, comRec, iDB, permission.toSet)
        } else {
          apk.model.updateIntentFilterDB(iDB)
        }
    }
    isetEmpty
  }
}
