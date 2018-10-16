/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.interprocedural

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.flow.pta.{FieldSlot, Instance, PTAResult, VarSlot}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util.{ISet, _}

trait IndirectCall {
  def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean
  def guessCallTarget(global: Global, signature: Signature): ISet[JawaMethod]
  def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact])
}

class RunnableStartRun extends IndirectCall {
  private val start: Signature = new Signature("Ljava/lang/Runnable;.start:()V")
  private val run: Signature = new Signature("Ljava/lang/Runnable;.run:()V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    val clazz = global.getClassOrResolve(typ)
    val runnable = global.getClassOrResolve(start.getClassType)
    runnable.isAssignableFrom(clazz) && subSig == start.getSubSignature
  }

  def guessCallTarget(global: Global, signature: Signature): ISet[JawaMethod] = {
    val newsig = new Signature(signature.getClassType, run.methodName, run.proto)
    CallHandler.resolveSignatureBasedCall(global, newsig, "virtual")
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      val fieldSlot = FieldSlot(ins, Constants.THREAD_RUNNABLE)
      val runnableInss = pTAResult.pointsToSet(callerContext, fieldSlot)
      runnableInss foreach { runnableIns =>
        val clazz = global.getClassOrResolve(runnableIns.typ)
        val runnable = global.getClassOrResolve(run.getClassType)
        if (runnable.isAssignableFrom(clazz)) {
          clazz.getMethod(run.getSubSignature) match {
            case Some(m) => callees += ((m, runnableIns))
            case None =>
          }
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact] = (factsToCallee, args, params) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val result = msetEmpty[RFAFact]
    val killFacts = msetEmpty[RFAFact]
    val argSlot = VarSlot(args.head)
    val paramSlot = VarSlot(params.head)
    varFacts.foreach { varFact =>
      if(varFact.s.getId == argSlot.getId) {
        val runnableSlot = FieldSlot(varFact.v, Constants.THREAD_RUNNABLE)
        factsToCallee.foreach { fact =>
          if(fact.s == runnableSlot) {
            result += RFAFact(paramSlot, fact.v)
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
    val clazz = global.getClassOrResolve(typ)
    val executor = global.getClassOrResolve(start.getClassType)
    executor.isAssignableFrom(clazz) && subSig == start.getSubSignature
  }

  def guessCallTarget(global: Global, signature: Signature): ISet[JawaMethod] = isetEmpty

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]) = {
    val varSlot = VarSlot(args(1))
    val runnableInss = pTAResult.pointsToSet(callerContext, varSlot)
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    runnableInss.foreach { runnableIns =>
      val clazz = global.getClassOrResolve(runnableIns.typ)
      val runnable = global.getClassOrResolve(run.getClassType)
      if (runnable.isAssignableFrom(clazz)) {
        clazz.getMethod(run.getSubSignature) match {
          case Some(m) => callees += ((m, runnableIns))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact] = (factsToCallee, args, params) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val result = msetEmpty[RFAFact]
    val argSlot = VarSlot(args(1))
    val paramSlot = VarSlot(params.head)
    varFacts.foreach { varFact =>
      if(varFact.s.getId == argSlot.getId) {
        result += RFAFact(paramSlot, varFact.v)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

class HandlerMessage extends IndirectCall {
  private val dispatchMessage: Signature = new Signature("Landroid/os/Handler;.dispatchMessage:(Landroid/os/Message;)V")
  private val handleMessage: Signature = new Signature("Landroid/os/Handler;.handleMessage:(Landroid/os/Message;)V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    val clazz = global.getClassOrResolve(typ)
    val handler = global.getClassOrResolve(dispatchMessage.getClassType)
    handler.isAssignableFrom(clazz) && subSig == dispatchMessage.getSubSignature
  }

  def guessCallTarget(global: Global, signature: Signature): ISet[JawaMethod] = {
    val newsig = new Signature(signature.getClassType, handleMessage.methodName, handleMessage.proto)
    CallHandler.resolveSignatureBasedCall(global, newsig, "virtual")
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      val clazz = global.getClassOrResolve(ins.typ)
      val handler = global.getClassOrResolve(handleMessage.getClassType)
      if (handler.isAssignableFrom(clazz)) {
        clazz.getMethod(handleMessage.getSubSignature) match {
          case Some(m) => callees += ((m, ins))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact] = (factsToCallee, args, params) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val argSlots = args.map(VarSlot)
    val paramSlots = params.map(VarSlot)
    val result = msetEmpty[RFAFact]

    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val paramSlot = paramSlots(i)
      varFacts.foreach{ fact =>
        if(fact.s.getId == argSlot.getId) result += RFAFact(paramSlot, fact.v)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

class AsyncTask extends IndirectCall {
  private val execute: Signature = new Signature("Landroid/os/AsyncTask;.execute:([Ljava/lang/Object;)Landroid/os/AsyncTask;")
  private val run: Signature = new Signature("Landroid/os/AsyncTask;.run:([Ljava/lang/Object;)V")

  override def isIndirectCall(global: Global, typ: JawaType, subSig: String): Boolean = {
    val clazz = global.getClassOrResolve(typ)
    val asyncTask = global.getClassOrResolve(execute.getClassType)
    asyncTask.isAssignableFrom(clazz) && subSig == execute.getSubSignature
  }

  def guessCallTarget(global: Global, signature: Signature): ISet[JawaMethod] = {
    val newsig = new Signature(signature.getClassType, run.methodName, run.proto)
    CallHandler.resolveSignatureBasedCall(global, newsig, "virtual")
  }

  override def getCallTarget(global: Global, inss: ISet[Instance], callerContext: Context, args: IList[String], pTAResult: PTAResult): (ISet[(JawaMethod, Instance)], (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]) = {
    val callees: MSet[(JawaMethod, Instance)] = msetEmpty
    inss.foreach { ins =>
      val clazz = global.getClassOrResolve(ins.typ)
      val asyncTask = global.getClassOrResolve(run.getClassType)
      if (asyncTask.isAssignableFrom(clazz)) {
        clazz.getMethod(run.getSubSignature) match {
          case Some(m) => callees += ((m, ins))
          case None =>
        }
      }
    }
    (callees.toSet, mapFactsToCallee)
  }

  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact] = (factsToCallee, args, params) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val argSlots = args.map(VarSlot)
    val paramSlots = params.map(VarSlot)
    val result = msetEmpty[RFAFact]
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val paramSlot = paramSlots(i)
      varFacts.foreach{ fact =>
        if(fact.s.getId == argSlot.getId) result += RFAFact(paramSlot, fact.v)
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
  addCall(new RunnableStartRun)
  addCall(new ExecutorExecuteRun)
  addCall(new HandlerMessage)
  addCall(new AsyncTask)

  def getCallResolver(global: Global, typ: JawaType, subSig: String): Option[IndirectCall] = {
    indirectCallResolvers.find { c =>
      c.isIndirectCall(global, typ, subSig)
    }
  }
}