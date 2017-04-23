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
import org.argus.jawa.alir.pta.{FieldSlot, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.{Constants, JawaMethod}
import org.argus.jawa.core.util.{ISet, isetEmpty}

/**
  * Created by fgwei on 4/21/17.
  */
class ThreadModel extends ModelCall {
  val TITLE = "ThreadModel"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("java.lang.Thread")

  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    val delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match {
      case "Ljava/lang/Thread;.<init>:()V" =>
        newFacts = getRunnable(s, args.head, args.head, currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/Runnable;)V" =>
        newFacts = getRunnable(s, args.head, args(1), currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/Runnable;Ljava/lang/String;)V" =>
        newFacts = getRunnable(s, args.head, args(1), currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/String;)V" =>
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;)V" =>
        newFacts = getRunnable(s, args.head, args(2), currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;)V" =>
        newFacts = getRunnable(s, args.head, args(2), currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;J)V" =>
        newFacts = getRunnable(s, args.head, args(2), currentContext)
        byPassFlag = false
      case "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/String;)V" =>
      case "Ljava/lang/Thread;.activeCount:()I" =>
      case "Ljava/lang/Thread;.checkAccess:()V" =>
      case "Ljava/lang/Thread;.clone:()Ljava/lang/Object;" =>
      case "Ljava/lang/Thread;.countStackFrames:()I" =>
      case "Ljava/lang/Thread;.currentThread:()Ljava/lang/Thread;" =>
      case "Ljava/lang/Thread;.destroy:()V" =>
      case "Ljava/lang/Thread;.dumpStack:()V" =>
      case "Ljava/lang/Thread;.enumerate:([Ljava/lang/Thread;)I" =>
      case "Ljava/lang/Thread;.getAllStackTraces:()Ljava/util/Map;" =>
      case "Ljava/lang/Thread;.getContextClassLoader:()Ljava/lang/ClassLoader;" =>
      case "Ljava/lang/Thread;.getDefaultUncaughtExceptionHandler:()Ljava/lang/Thread$UncaughtExceptionHandler;" =>
      case "Ljava/lang/Thread;.getId:()J" =>
      case "Ljava/lang/Thread;.getName:()Ljava/lang/String;" =>
      case "Ljava/lang/Thread;.getPriority:()I" =>
      case "Ljava/lang/Thread;.getStackTrace:()[Ljava/lang/StackTraceElement;" =>
      case "Ljava/lang/Thread;.getState:()Ljava/lang/Thread$State;" =>
      case "Ljava/lang/Thread;.getThreadGroup:()Ljava/lang/ThreadGroup;" =>
      case "Ljava/lang/Thread;.getUncaughtExceptionHandler:()Ljava/lang/Thread$UncaughtExceptionHandler;" =>
      case "Ljava/lang/Thread;.holdsLock:(Ljava/lang/Object;)Z" =>
      case "Ljava/lang/Thread;.interrupt:()V" =>
      case "Ljava/lang/Thread;.interrupted:()Z" =>
      case "Ljava/lang/Thread;.isAlive:()Z" =>
      case "Ljava/lang/Thread;.isDaemon:()Z" =>
      case "Ljava/lang/Thread;.isInterrupted:()Z" =>
      case "Ljava/lang/Thread;.join:()V" =>
      case "Ljava/lang/Thread;.join:(J)V" =>
      case "Ljava/lang/Thread;.join:(JI)V" =>
      case "Ljava/lang/Thread;.resume:()V" =>
      case "Ljava/lang/Thread;.run:()V" =>
      case "Ljava/lang/Thread;.setContextClassLoader:(Ljava/lang/ClassLoader;)V" =>
      case "Ljava/lang/Thread;.setDaemon:(Z)V" =>
      case "Ljava/lang/Thread;.setDefaultUncaughtExceptionHandler:(Ljava/lang/Thread$UncaughtExceptionHandler;)V" =>
      case "Ljava/lang/Thread;.setName:(Ljava/lang/String;)V" =>
      case "Ljava/lang/Thread;.setPriority:(I)V" =>
      case "Ljava/lang/Thread;.setUncaughtExceptionHandler:(Ljava/lang/Thread$UncaughtExceptionHandler;)V" =>
      case "Ljava/lang/Thread;.sleep:(J)V" =>
      case "Ljava/lang/Thread;.sleep:(JI)V" =>
      case "Ljava/lang/Thread;.start:()V" =>
      case "Ljava/lang/Thread;.stop:()V" =>
      case "Ljava/lang/Thread;.stop:(Ljava/lang/Throwable;)V" =>
      case "Ljava/lang/Thread;.suspend:()V" =>
      case "Ljava/lang/Thread;.toString:()Ljava/lang/String;" =>
      case "Ljava/lang/Thread;.yield:()V" =>
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }

  private def getRunnable(s: PTAResult, thisArg: String, arg: String, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val thisSlot = VarSlot(thisArg, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val runnableSlot = VarSlot(arg, isBase = false, isArg = true)
    val runnableValue = s.pointsToSet(runnableSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv => newfacts ++= runnableValue.map(new RFAFact(FieldSlot(tv, Constants.THREAD_RUNNABLE), _))
    }
    newfacts
  }
}
