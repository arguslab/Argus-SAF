/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.amandroid.core.parser.{IntentFilter, IntentFilterDataBase}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.{Global, JavaKnowledge, JawaMethod, JawaType}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object FrameworkMethodsModel {
  
  final val TITLE = "FrameworkMethodsModel"
  
  def isFrameworkMethods(p: JawaMethod): Boolean = {
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

  def doFrameworkMethodsModelCall(global: Global, apk: Apk, s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSubSignature match {
      case "setContentView:(I)V" =>
      case "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;" =>
        require(retVars.size == 1)
        newFacts ++= registerReceiver(global, apk, s, args, retVars.head, currentContext)
        byPassFlag = false
      case "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;" => 
        require(retVars.size == 1)
        newFacts ++= registerReceiver(global, apk, s, args, retVars.head, currentContext)
        byPassFlag = false
      case "getApplication:()Landroid/app/Application;" =>
        require(retVars.size == 1)
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.Application"), retVars.head, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case "getSystemService:(Ljava/lang/String;)Ljava/lang/Object;" =>
        require(retVars.size == 1)
        newFacts ++= getSystemService(global, s, args, retVars.head, currentContext)
  //      byPassFlag = false
      case "getBaseContext:()Landroid/content/Context;" =>
        require(retVars.size == 1)
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.ContextImpl"), retVars.head, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case "getApplicationContext:()Landroid/content/Context;"=>
        require(retVars.size == 1)
        ReachingFactsAnalysisHelper.getReturnFact(new JawaType("android.app.Application"), retVars.head, currentContext) match{
          case Some(f) => newFacts += f
          case None =>
        }
        byPassFlag = false
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }

  private def registerReceiver(global: Global, apk: Apk, s: PTAResult, args: List[String], retVar: String, currentContext: Context): ISet[RFAFact] ={
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
        val comRec = global.getClassOrResolve(rv.typ)
        filterValue.foreach {
          fv =>
            val mActionsSlot = FieldSlot(fv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENTFILTER_ACTIONS))
            val mActionsValue = s.pointsToSet(mActionsSlot, currentContext)
            mActionsValue.foreach {
              case PTAConcreteStringInstance(text, _) =>
                intentF.addAction(text)
              case _ =>
                intentF.addAction("ANY")
            }
            val mCategoriesSlot = FieldSlot(fv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENTFILTER_CATEGORIES))
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
        if (!apk.hasEnv(rv.typ)) {
          AppInfoCollector.dynamicRegisterReceiver(apk, comRec, iDB, permission.toSet, global.reporter)
        } else {
          apk.updateIntentFilterDB(iDB)
        }
    }
    isetEmpty
  }

  private def getSystemService(global: Global, s: PTAResult, args: List[String], retVar: String, currentContext: Context): ISet[RFAFact] ={
    val result = isetEmpty[RFAFact]
    require(args.size >1)
    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramValue = s.pointsToSet(paramSlot, currentContext)
    paramValue.foreach {
      case cstr@PTAConcreteStringInstance(text, _) =>
        if (AndroidConstants.getSystemServiceStrings.contains(text)) {
          global.reporter.echo(TITLE, "Get " + text + " service in " + currentContext)
        } else {
          global.reporter.echo(TITLE, "Given service does not exist: " + cstr)
        }
      case pstr@PTAPointStringInstance(_) => global.reporter.echo(TITLE, "Get system service use point string: " + pstr)
      case str => global.reporter.echo(TITLE, "Get system service use unexpected instance type: " + str)
    }
    result
  }
}
