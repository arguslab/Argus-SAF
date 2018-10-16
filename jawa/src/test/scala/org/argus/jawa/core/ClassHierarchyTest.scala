/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.argus.jawa.core.io.NoReporter
import org.scalatest.{FlatSpec, Matchers}
import org.argus.jawa.core.util.FileUtil

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ClassHierarchyTest extends FlatSpec with Matchers {

  "Load android.app.Activity" should "resolve android.content.ContextWrapper in Hierarchy" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.resolved(global.getClassOrResolve(new JawaType("android.content.ContextWrapper"))))
  }

  "Load android.app.Activity" should "let java.lang.Object getAllSubClassesOfIncluding have 5 results" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.getClassOrResolve(new JawaType("android.app.Activity"))
    val Object = global.getClassOrResolve(JavaKnowledge.OBJECT)
    assert(global.getClassHierarchy.getAllSubClassesOfIncluding(Object).size == 5)
  }

  "Load android.app.Activity" should "let java.lang.Object getAllSubClassesOf have 4 subclasses" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.getClassOrResolve(new JawaType("android.app.Activity"))
    val Object = global.getClassOrResolve(JavaKnowledge.OBJECT)
    assert(global.getClassHierarchy.getAllSubClassesOf(Object).size == 4)
  }

  "android.app.Activity" should "have 5 superclasses including itself" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.getAllSuperClassesOfIncluding(activity).size == 5)
  }

  "android.app.Activity" should "have 4 superclasses" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.getAllSuperClassesOf(activity).size == 4)
  }

  "com.ksu.fieldFlowSentivity.MainActivity" should "have 5 superclasses and assignable to Activity" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val mainActivity = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.getAllSuperClassesOf(mainActivity).size == 5 && activity.isAssignableFrom(mainActivity))
  }

  "Load android.nfc.tech.TagTechnology" should "let java.lang.AutoCloseable get 3 subinterface including itself and assignable" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val tag = global.getClassOrResolve(new JawaType("android.nfc.tech.TagTechnology"))
    val closeable = global.getClassOrResolve(new JawaType("java.lang.AutoCloseable"))
    assert(global.getClassHierarchy.getAllSubInterfacesOfIncluding(closeable).size == 3 && closeable.isAssignableFrom(tag))
  }

  "Load android.nfc.tech.TagTechnology" should "let java.lang.AutoCloseable get 2 subinterface" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.getClassOrResolve(new JawaType("android.nfc.tech.TagTechnology"))
    val closeable = global.getClassOrResolve(new JawaType("java.lang.AutoCloseable"))
    assert(global.getClassHierarchy.getAllSubInterfacesOf(closeable).size == 2)
  }

  "Load com.ksu.fieldFlowSentivity.MainActivity and com.ksu.fieldFlowSentivity.FooActivity" should "let android.app.Activity have 3 subclasses including itself" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.FooActivity"))
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.getSubClassesOfIncluding(activity).size == 3)
  }

  "Load com.ksu.fieldFlowSentivity.MainActivity and com.ksu.fieldFlowSentivity.FooActivity" should "let android.app.Activity have 2 subclasses" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.FooActivity"))
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.getSubClassesOf(activity).size == 2)
  }

  "Load android.nfc.tech.TagTechnology" should "let java.lang.AutoCloseable get subinterface java.io.Closeable" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.getClassOrResolve(new JawaType("android.nfc.tech.TagTechnology"))
    val closeable = global.getClassOrResolve(new JawaType("java.lang.AutoCloseable"))
    assert(global.getClassHierarchy.getSubInterfacesOfIncluding(closeable).map(_.getType).contains(new JawaType("java.io.Closeable")))
  }

  "Load com.ksu.fieldFlowSentivity.MainActivity" should "let android.view.LayoutInflater$Factory get implementer android.app.Activity" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val factory = global.getClassOrResolve(new JawaType("android.view.LayoutInflater$Factory"))
    assert(global.getClassHierarchy.getAllImplementersOf(factory).map(_.getType).contains(new JawaType("android.app.Activity")))
  }

  "com.ksu.fieldFlowSentivity.MainActivity" should "recursively subclass of java.lang.Object" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val mainActivity = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val Object = global.getClassOrResolve(JavaKnowledge.OBJECT)
    assert(global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(mainActivity, Object))
  }

  "com.ksu.fieldFlowSentivity.MainActivity" should "be subclass of android.app.Activity" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val mainActivity = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    assert(global.getClassHierarchy.isClassSubClassOf(mainActivity, activity))
  }

  "onCreate" should "be visible from com.ksu.fieldFlowSentivity.MainActivity" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val mainActivity = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val ms = global.getClassOrResolve(new JawaType("android.app.Activity")).getDeclaredMethodsByName("onCreate")
    assert(ms.forall(m => global.getClassHierarchy.isMethodVisible(mainActivity, m)))
  }

  "com.ksu.fieldFlowSentivity.MainActivity.isDestroyed" should "be dispatched to android.app.Activity.isDestroyed" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val c: JawaClass = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.MainActivity"))
    val m: JawaMethod = global.getClassOrResolve(new JawaType("android.app.Activity")).getDeclaredMethodByName("isDestroyed").get
    assert(global.getClassHierarchy.resolveConcreteDispatch(c, m).get.getDeclaringClass.getName == "android.app.Activity")
  }

  "android.app.Activity with process" should "be abstract dispatched to com.ksu.fieldFlowSentivity.FooActivity.process" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val c: JawaClass = global.getClassOrResolve(new JawaType("android.app.Activity"))
    val m: JawaMethod = global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.FooActivity")).getDeclaredMethodByName("process").get
    assert(global.getClassHierarchy.resolveAbstractDispatch(c, m).exists(m => m.getDeclaringClass.getName == "com.ksu.fieldFlowSentivity.FooActivity"))
  }

  "reset" should "clear all" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    val activity = global.getClassOrResolve(new JawaType("android.app.Activity"))
    global.getClassOrResolve(new JawaType("com.ksu.fieldFlowSentivity.FooActivity"))
    global.getClassHierarchy.reset()
    assert(!global.getClassHierarchy.resolved(activity))
  }
}
