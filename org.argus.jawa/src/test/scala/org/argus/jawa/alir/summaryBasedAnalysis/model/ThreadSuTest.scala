/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis.model

import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/15/17.
  */
class ThreadSuTest extends SuTestBase("Thread.safsu") {

  val thisInstance = PTAInstance(JavaKnowledge.THREAD, defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)
  val thisRunnableInstance = PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext)
  val thisRunnableFact = new RFAFact(FieldSlot(thisInstance, "runnable"), thisRunnableInstance)
  val thisNameInstance = PTAConcreteStringInstance("myThread", defContext)
  val thisNameFact = new RFAFact(FieldSlot(thisInstance, "name"), thisNameInstance)
  val thisHandlerInstance = PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext)
  val thisHandlerFact = new RFAFact(FieldSlot(thisInstance, "handler"), thisHandlerInstance)

  "Ljava/lang/Thread;.<init>:()V" with_input (
    thisFact,
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "runnable"), thisInstance),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/Runnable;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/Runnable;Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("HelloThread", defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("HelloThread", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("HelloThread", defContext3))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("HelloThread", defContext2))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("HelloThread", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), thisInstance),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("HelloThread", defContext2))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v3"), PTAConcreteStringInstance("HelloThread", defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v3"), PTAConcreteStringInstance("HelloThread", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("HelloThread", defContext3))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;J)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v3"), PTAConcreteStringInstance("HelloThread", defContext3))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(VarSlot("v3"), PTAConcreteStringInstance("HelloThread", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), PTAInstance(new JawaType("java.lang.Runnable").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("HelloThread", defContext3))
  )

  "Ljava/lang/Thread;.<init>:(Ljava/lang/ThreadGroup;Ljava/lang/String;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("HelloThread", defContext2))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("HelloThread", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "runnable"), thisInstance),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("HelloThread", defContext2))
  )

  "Ljava/lang/Thread;.activeCount:()I" with_input () produce ()

  "Ljava/lang/Thread;.checkAccess:()V" with_input () produce ()

  "Ljava/lang/Thread;.clone:()Ljava/lang/Object;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/Thread;.countStackFrames:()I" with_input () produce ()

  "Ljava/lang/Thread;.currentThread:()Ljava/lang/Thread;" with_input () produce new RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.THREAD.toUnknown, currentContext))

  "Ljava/lang/Thread;.destroy:()V" with_input () produce ()

  "Ljava/lang/Thread;.dumpStack:()V" with_input () produce ()

  "Ljava/lang/Thread;.enumerate:([Ljava/lang/Thread;)I" with_input () produce ()

  "Ljava/lang/Thread;.getAllStackTraces:()Ljava/util/Map;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashMap"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), currentContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext), "key"), PTAInstance(JavaKnowledge.THREAD.toUnknown, currentContext)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext), PTAInstance(JavaKnowledge.THREAD.toUnknown, currentContext)), PTAInstance(new JawaType("java.lang.StackTrackElement", 1), currentContext)),
    new RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.StackTrackElement", 1), currentContext)), PTAInstance(new JawaType("java.lang.StackTrackElement"), currentContext))
  )

  "Ljava/lang/Thread;.getContextClassLoader:()Ljava/lang/ClassLoader;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, currentContext))
  )

  "Ljava/lang/Thread;.getDefaultUncaughtExceptionHandler:()Ljava/lang/Thread$UncaughtExceptionHandler;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("temp"), thisHandlerInstance)
  )

  "Ljava/lang/Thread;.getId:()J" with_input () produce ()

  "Ljava/lang/Thread;.getName:()Ljava/lang/String;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), thisNameInstance)
  )

  "Ljava/lang/Thread;.getPriority:()I" with_input () produce ()

  "Ljava/lang/Thread;.getStackTrace:()[Ljava/lang/StackTraceElement;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.StackTraceElement", 1), currentContext)),
    new RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.StackTraceElement", 1), currentContext)), PTAInstance(new JawaType("java.lang.StackTraceElement"), currentContext))
  )

  "Ljava/lang/Thread;.getState:()Ljava/lang/Thread$State;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Thread$State"), currentContext))
  )

  "Ljava/lang/Thread;.getThreadGroup:()Ljava/lang/ThreadGroup;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.ThreadGroup"), currentContext))
  )

  "Ljava/lang/Thread;.getUncaughtExceptionHandler:()Ljava/lang/Thread$UncaughtExceptionHandler;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("temp"), thisHandlerInstance)
  )

  "Ljava/lang/Thread;.holdsLock:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/lang/Thread;.interrupt:()V" with_input () produce ()

  "Ljava/lang/Thread;.interrupted:()Z" with_input () produce ()

  "Ljava/lang/Thread;.isAlive:()Z" with_input () produce ()

  "Ljava/lang/Thread;.isDaemon:()Z" with_input () produce ()

  "Ljava/lang/Thread;.isInterrupted:()Z" with_input () produce ()

  "Ljava/lang/Thread;.join:()V" with_input () produce ()

  "Ljava/lang/Thread;.join:(J)V" with_input () produce ()

  "Ljava/lang/Thread;.join:(JI)V" with_input () produce ()

  "Ljava/lang/Thread;.resume:()V" with_input () produce ()

  "Ljava/lang/Thread;.run:()V" with_input () produce ()

  "Ljava/lang/Thread;.setContextClassLoader:(Ljava/lang/ClassLoader;)V" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, defContext2))
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, defContext2)),
    new RFAFact(FieldSlot(thisInstance, "loader"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, defContext2))
  )

  "Ljava/lang/Thread;.setDaemon:(Z)V" with_input () produce ()

  "Ljava/lang/Thread;.setDefaultUncaughtExceptionHandler:(Ljava/lang/Thread$UncaughtExceptionHandler;)V" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2))
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2)),
    new RFAFact(FieldSlot(thisInstance, "handler"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2))
  )

  "Ljava/lang/Thread;.setName:(Ljava/lang/String;)V" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("newThread", defContext2))
  ) produce (
    thisFact,
    thisRunnableFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("newThread", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("newThread", defContext2))
  )

  "Ljava/lang/Thread;.setPriority:(I)V" with_input () produce ()

  "Ljava/lang/Thread;.setUncaughtExceptionHandler:(Ljava/lang/Thread$UncaughtExceptionHandler;)V" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2))
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    thisHandlerFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2)),
    new RFAFact(FieldSlot(thisInstance, "handler"), PTAInstance(new JawaType("java.lang.Thread$UncaughtExceptionHandler"), defContext2))
  )

  "Ljava/lang/Thread;.sleep:(J)V" with_input () produce ()

  "Ljava/lang/Thread;.sleep:(JI)V" with_input () produce ()

  "Ljava/lang/Thread;.start:()V" with_input () produce ()

  "Ljava/lang/Thread;.stop:()V" with_input () produce ()

  "Ljava/lang/Thread;.stop:(Ljava/lang/Throwable;)V" with_input () produce ()

  "Ljava/lang/Thread;.suspend:()V" with_input () produce ()

  "Ljava/lang/Thread;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisRunnableFact,
    thisNameFact
  ) produce (
    thisFact,
    thisRunnableFact,
    thisNameFact,
    new RFAFact(VarSlot("temp"), thisNameInstance)
  )

  "Ljava/lang/Thread;.yield:()V" with_input () produce ()
}
