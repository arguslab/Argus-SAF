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

import org.argus.jawa.core.elements.{AccessFlag, JawaType}
import org.argus.jawa.core.io.NoReporter
import org.scalatest.{FlatSpec, Matchers}
import org.argus.jawa.core.util.FileUtil

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class GlobalTest extends FlatSpec with Matchers {
  "Load code" should "have size 4" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    assert(global.getApplicationClassCodes.size == 4)
  }

  "Load code" should "have given type" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    assert(global.getApplicationClassCodes.contains(new JawaType("com.ksu.fieldFlowSentivity.MainActivity")))
  }

  "Given type" should "in application category" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    assert(global.isApplicationClasses(new JawaType("com.ksu.fieldFlowSentivity.MainActivity")) && global.getClassCategoryFromClassPath(new JawaType("com.ksu.fieldFlowSentivity.MainActivity")) == global.ClassCategory.APPLICATION)
  }

  "Given type" should "in library category" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    assert(global.isSystemLibraryClasses(new JawaType("java.lang.Object"))&& global.getClassCategoryFromClassPath(new JawaType("java.lang.Object")) == global.ClassCategory.SYSTEM_LIBRARY)
  }

  "Class path" should "contains given type" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    assert(global.containsClass(new JawaType("java.lang.Object")))
  }

  "MyClass for java.lang.Object" should "have following content" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val myClass = global.getMyClass(new JawaType("java.lang.Object")).get
    assert(
      AccessFlag.isPublic(myClass.accessFlag) &&
      myClass.typ == new JawaType("java.lang.Object") &&
      myClass.superType.isEmpty &&
      myClass.interfaces.isEmpty &&
      myClass.outerType.isEmpty
    )
  }

  "MyClass for android.app.Activity" should "have following content" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    val myClass = global.getMyClass(new JawaType("android.app.Activity")).get
    assert(
      AccessFlag.isPublic(myClass.accessFlag) &&
      myClass.typ == new JawaType("android.app.Activity") &&
      myClass.superType.isDefined &&
      myClass.superType.get.equals(new JawaType("android.view.ContextThemeWrapper")) &&
      myClass.interfaces.size == 5 &&
      myClass.outerType.isEmpty
    )
  }

  "getClazz for java.lang.Object" should "return a JawaClass" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    assert(global.getClazz(new JawaType("java.lang.Object")).isDefined)
  }

  "getClazz for java.lang.Object1" should "return None" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    assert(global.getClazz(new JawaType("java.lang.Object1")).isEmpty)
  }

  "getClassOrResolve for java.lang.Object1" should "return an unknown JawaClass" in {
    val global = new Global("test", new NoReporter)
    global.setJavaLib(getClass.getResource("/libs/android.jar").getPath)
    assert(global.getClassOrResolve(new JawaType("java.lang.Object1")).isUnknown)
  }

  "Get application classes" should "return 4 classes" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    assert(global.getApplicationClasses.size == 4)
  }

  "Get user library classes" should "return empty" in {
    val srcUri = FileUtil.toUri(getClass.getResource("/test1").getPath)
    val global = new Global("test", new NoReporter)
    global.load(srcUri ,Constants.JAWA_FILE_EXT)
    assert(global.getUserLibraryClasses.isEmpty)
  }

}
