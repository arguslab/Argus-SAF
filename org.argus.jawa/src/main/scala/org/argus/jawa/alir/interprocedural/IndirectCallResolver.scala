/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.interprocedural

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.alir.pta.{FieldSlot, Instance, PTAResult, VarSlot}
import org.argus.jawa.core.{Global, JawaMethod, JawaType, Signature}
import org.argus.jawa.core.util.{ISet, _}

trait IndirectCall {
  def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean
  def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact])
}

class ThreadStartRun extends IndirectCall {
  private val start: Signature = new Signature("Ljava/lang/Thread;.start:()V")
  private val run: Signature = new Signature("Ljava/lang/Runnable;.run:()V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(typ, start.getClassType) && subSig == start.getSubSignature
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      val fieldSlot = FieldSlot(ins, "runnable")
      val runnableInss = pTAResult.pointsToSet(fieldSlot, callerContext)
      runnableInss foreach { runnableIns =>
        if (global.getClassHierarchy.getAllImplementersOf(run.getClassType).contains(runnableIns.typ)) {
          global.getClassOrResolve(runnableIns.typ).getMethod(run.getSubSignature) match {
            case Some(m) => callees += ((m, runnableIns))
            case None =>
          }
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact] = (factsToCallee, args, params, factory) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val result = msetEmpty[RFAFact]
    val killFacts = msetEmpty[RFAFact]
    val argSlot = VarSlot(args.head, isBase = false, isArg = true)
    val paramSlot = VarSlot(params.head, isBase = false, isArg = false)
    varFacts.foreach { varFact =>
      if(varFact.s.getId == argSlot.getId) {
        val runnableSlot = FieldSlot(varFact.v, "runnable")
        factsToCallee.foreach { fact =>
          if(fact.s == runnableSlot) {
            result += new RFAFact(paramSlot, fact.v)(factory)
            killFacts += fact
          }
        }
      }
    }
    factsToCallee -- varFacts -- killFacts ++ result
  }
}

class ExecutorExecuteRun extends IndirectCall {
  private val start: Signature = new Signature("Ljava/util/concurrent/ExecutorService;.execute:(Ljava/lang/Runnable;)V")
  private val run: Signature = new Signature("Ljava/lang/Runnable;.run:()V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(typ, start.getClassType) && subSig == start.getSubSignature
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact]) = {
    val varSlot = VarSlot(args(1), isBase = false, isArg = true)
    val runnableInss = pTAResult.pointsToSet(varSlot, callerContext)
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    runnableInss.foreach { runnableIns =>
      if (global.getClassHierarchy.getAllImplementersOf(run.getClassType).contains(runnableIns.typ)) {
        global.getClassOrResolve(runnableIns.typ).getMethod(run.getSubSignature) match {
          case Some(m) => callees += ((m, runnableIns))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact] = (factsToCallee, args, params, factory) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val result = msetEmpty[RFAFact]
    val argSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramSlot = VarSlot(params.head, isBase = false, isArg = false)
    varFacts.foreach { varFact =>
      if(varFact.s.getId == argSlot.getId) {
        result += new RFAFact(paramSlot, varFact.v)(factory)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

class HandlerMessage extends IndirectCall {
  private val dispatchMessage: Signature = new Signature("Landroid/os/Handler;.dispatchMessage:(Landroid/os/Message;)V")
  private val handleMessage: Signature = new Signature("Landroid/os/Handler;.handleMessage:(Landroid/os/Message;)V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(typ, dispatchMessage.getClassType) && subSig == dispatchMessage.getSubSignature
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      if (global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(ins.typ, handleMessage.getClassType)) {
        global.getClassOrResolve(ins.typ).getMethod(handleMessage.getSubSignature) match {
          case Some(m) => callees += ((m, ins))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact] = (factsToCallee, args, params, factory) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val argSlots = args.map(VarSlot(_, isBase = false, isArg = true))
    val paramSlots = params.map(VarSlot(_, isBase = false, isArg = false))
    val result = msetEmpty[RFAFact]

    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val paramSlot = paramSlots(i)
      varFacts.foreach{ fact =>
        if(fact.s.getId == argSlot.getId) result += new RFAFact(paramSlot, fact.v)(factory)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

class AsyncTask extends IndirectCall {
  private val execute: Signature = new Signature("Landroid/os/AsyncTask;.execute:([Ljava/lang/Object;)Landroid/os/AsyncTask;")
  private val run: Signature = new Signature("Landroid/os/AsyncTask;.run:([Ljava/lang/Object;)V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(typ, execute.getClassType) && subSig == execute.getSubSignature
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      if (global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(ins.typ, run.getClassType)) {
        global.getClassOrResolve(ins.typ).getMethod(run.getSubSignature) match {
          case Some(m) => callees += ((m, ins))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String], RFAFactFactory) => ISet[RFAFact] = (factsToCallee, args, params, factory) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val argSlots = args.map(VarSlot(_, isBase = false, isArg = true))
    val paramSlots = params.map(VarSlot(_, isBase = false, isArg = false))
    val result = msetEmpty[RFAFact]
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val paramSlot = paramSlots(i)
      varFacts.foreach{ fact =>
        if(fact.s.getId == argSlot.getId) result += new RFAFact(paramSlot, fact.v)(factory)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

/**
  * Created by fgwei on 4/21/17.
  */
object IndirectCallResolver {
  /**
    * Map to store indirect calls, e.g., Ljava/lang/Thread;.start:()V -> Ljava/lang/Runnable;.run:()V
    * Only handle non-static calls for now .
    */
  private var indirectCallResolvers: ISet[IndirectCall] = isetEmpty
  def addCall(call: IndirectCall): Unit = this.indirectCallResolvers += call
  addCall(new ThreadStartRun)
  addCall(new ExecutorExecuteRun)
  addCall(new HandlerMessage)
  addCall(new AsyncTask)
//  addCallMap(new Signature("Ljava/util/concurrent/ExecutorService;.execute:(Ljava/lang/Runnable;)V"), CallInfo(new Signature("Ljava/lang/Thread;.run:()V")))
//  addCallMap(new Signature("Landroid/os/Handler;.dispatchMessage:(Landroid/os/Message;)V"), CallInfo(new Signature("Landroid/os/Handler;.handleMessage:(Landroid/os/Message;)V")))

  def getCallResolver(global: Global, typ: JawaType, subSig: String): Option[IndirectCall] = {
    indirectCallResolvers.find { c =>
      c.isIndirectCall(global, typ, subSig)
    }
  }
}