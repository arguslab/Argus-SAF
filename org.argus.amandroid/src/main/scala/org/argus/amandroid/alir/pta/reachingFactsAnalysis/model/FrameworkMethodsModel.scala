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

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser.{IntentFilter, IntentFilterDataBase}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCall
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class FrameworkMethodsModel extends ModelCall {
  
  final val TITLE = "FrameworkMethodsModel"

  def isModelCall(p: JawaMethod): Boolean = {
    val contextRec = p.getDeclaringClass.global.getClassOrResolve(new JawaType("android.content.Context"))
    if(!p.getDeclaringClass.isInterface && p.getDeclaringClass.global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(p.getDeclaringClass.getType, contextRec.getType)){
      p.getSubSignature match{
        case "setContentView:(I)V" |
          "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;" |
          "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;" |
          "getApplication:()Landroid/app/Application;" |
          "getSystemService:(Ljava/lang/String;)Ljava/lang/Object;" |
          "getBaseContext:()Landroid/content/Context;" |
          "getApplicationContext:()Landroid/content/Context;"=> true
        case _ => false
      }
    }
    else false
  }

  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    val apk = p.getDeclaringClass.global.asInstanceOf[ApkGlobal]
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSubSignature match {
      case "setContentView:(I)V" =>
      case "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;" =>
        newFacts ++= registerReceiver(apk, s, args, retVar, currentContext)
        byPassFlag = false
      case "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;" => 
        newFacts ++= registerReceiver(apk, s, args, retVar, currentContext)
        byPassFlag = false
      case "getApplication:()Landroid/app/Application;" =>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.Application"), retVar, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case "getSystemService:(Ljava/lang/String;)Ljava/lang/Object;" =>
        newFacts ++= getSystemService(apk, s, args, retVar, currentContext)
  //      byPassFlag = false
      case "getBaseContext:()Landroid/content/Context;" =>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.ContextImpl"), retVar, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case "getApplicationContext:()Landroid/content/Context;"=>
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.Application"), retVar, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }

  private def registerReceiver(apk: ApkGlobal, s: PTAResult, args: List[String], retVar: String, currentContext: Context): ISet[RFAFact] ={
//    val resullt = msetEmpty[RFAFact]
    require(args.size > 2)
//    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
//    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val receiverSlot = VarSlot(args(1), isBase = false, isArg = true)
    val receiverValue = s.pointsToSet(receiverSlot, currentContext)
    val filterSlot = VarSlot(args(2), isBase = false, isArg = true)
    val filterValue = s.pointsToSet(filterSlot, currentContext)
    val permissionSlotOpt = 
      if(args.lift(3).isDefined) Some(VarSlot(args(3), isBase = false, isArg = true))
      else None
    val permissionValueOpt = 
      if(permissionSlotOpt.isDefined) Some(s.pointsToSet(permissionSlotOpt.get, currentContext))
      else None
    val iDB = new IntentFilterDataBase
    receiverValue.foreach {
      case ui if ui.isUnknown =>
      case rv =>
        val intentF = new IntentFilter(rv.typ)
        val comRec = apk.getClassOrResolve(rv.typ)
        filterValue.foreach {
          fv =>
            val mActionsSlot = FieldSlot(fv, AndroidConstants.INTENTFILTER_ACTIONS)
            val mActionsValue = s.pointsToSet(mActionsSlot, currentContext)
            mActionsValue.foreach {
              case PTAConcreteStringInstance(text, _) =>
                intentF.addAction(text)
              case _ =>
                intentF.addAction("ANY")
            }
            val mCategoriesSlot = FieldSlot(fv, AndroidConstants.INTENTFILTER_CATEGORIES)
            val mCategoriesValue = s.pointsToSet(mCategoriesSlot, currentContext)
            mCategoriesValue.foreach {
              case PTAConcreteStringInstance(text, _) =>
                intentF.addCategory(text)
              case _ =>
                intentF.addCategory("ANY")
            }
        }
        val permission: MSet[String] = msetEmpty
        permissionValueOpt.foreach {
          pvs =>
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

  private val systemServices: MSet[(Context, String)] = msetEmpty

  private def getSystemService(apk: ApkGlobal, s: PTAResult, args: List[String], retVar: String, currentContext: Context): ISet[RFAFact] ={
    val result = isetEmpty[RFAFact]
    require(args.size >1)
    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramValue = s.pointsToSet(paramSlot, currentContext)
    paramValue.foreach {
      case cstr@PTAConcreteStringInstance(text, _) =>
        if(!systemServices.contains((currentContext, text))) {
          if (AndroidConstants.getSystemServiceStrings.contains(text)) {
            apk.reporter.echo(TITLE, "Get " + text + " service in " + currentContext)
          } else {
            apk.reporter.echo(TITLE, "Given service does not exist: " + cstr)
          }
          systemServices.add((currentContext, text))
        }
      case pstr@PTAPointStringInstance(_) => apk.reporter.echo(TITLE, "Get system service use point string: " + pstr)
      case str => apk.reporter.echo(TITLE, "Get system service use unexpected instance type: " + str)
    }
    result
  }
}
