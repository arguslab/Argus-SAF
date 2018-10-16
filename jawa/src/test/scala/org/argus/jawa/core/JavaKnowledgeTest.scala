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

import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.scalatest.{FlatSpec, Matchers}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class JavaKnowledgeTest extends FlatSpec with Matchers {
  "int" should "be java primitive" in {
    assert(JavaKnowledge.isJavaPrimitive("int"))
  }

  "java.lang.Object" should "not be java primitive" in {
    assert(!JavaKnowledge.isJavaPrimitive("java.lang.Object"))
  }

  "int[][]" should "format to name [[I" in {
    assert(JavaKnowledge.formatTypeToName(new JawaType("int", 2)) == "[[I")
  }

  "java.lang.Object[][]" should "format to name [[Ljava.lang.Object;" in {
    assert(JavaKnowledge.formatTypeToName(new JawaType("java.lang.Object", 2)) == "[[Ljava.lang.Object;")
  }

  "int[][]" should "format to signature [[I" in {
    assert(JavaKnowledge.formatTypeToSignature(new JawaType("int", 2)) == "[[I")
  }

  "java.lang.Object[][]" should "format to signature [[Ljava/lang/Object;" in {
    assert(JavaKnowledge.formatTypeToSignature(new JawaType("java.lang.Object", 2)) == "[[Ljava/lang/Object;")
  }

  "java.lang.Object" should "separate to java.lang and Object" in {
    assert(JavaKnowledge.separatePkgAndTyp("java.lang.Object").packageName == "java.lang" && JavaKnowledge.separatePkgAndTyp("java.lang.Object").name == "Object")
  }

  "[Ljava.lang.String;" should "format to JawaType(java.lang.String, 1)" in {
    assert(JavaKnowledge.getTypeFromName("[Ljava.lang.String;") == new JawaType("java.lang.String", 1))
  }

  "java.lang.String[]" should "format to JawaType(java.lang.String, 1)" in {
    assert(JavaKnowledge.getTypeFromJawaName("java.lang.String[]") == new JawaType("java.lang.String", 1))
  }

  "[Ljava/lang/String;" should "format to JawaType(java.lang.String, 1)" in {
    assert(JavaKnowledge.formatSignatureToType("[Ljava/lang/String;") == new JawaType("java.lang.String", 1))
  }

  "android.os.Handler$Callback" should "have outer class android.os.Handler" in {
    assert(JavaKnowledge.getOuterTypeFrom(new JawaType("android.os.Handler$Callback")) == new JawaType("android.os.Handler"))
  }

  "android.app.Activity.onCreate(android.os.Bundle)void" should "have signature Landroid/app/Activity;.onCreate:(Landroid/os/Bundle;)V" in {
    assert(JavaKnowledge.genSignature("Landroid/app/Activity;", "onCreate", "(Landroid/os/Bundle;)V") == new Signature("Landroid/app/Activity;.onCreate:(Landroid/os/Bundle;)V"))
  }

  "JawaType(android.app.Activity) onCreate Set(JawaType(android.os.Bundle)) JawaType(void)" should "have signature Landroid/app/Activity;.onCreate:(Landroid/os/Bundle;)V" in {
    assert(JavaKnowledge.genSignature(new JawaType("android.app.Activity"), "onCreate", List(new JawaType("android.os.Bundle")), new JawaType("void")) == new Signature("Landroid/app/Activity;.onCreate:(Landroid/os/Bundle;)V"))
  }

  "java.lang.Throwable.stackState" should "be valid FQN" in {
    assert(JavaKnowledge.isFQN("java.lang.Throwable.stackState"))
  }

  "java.lang.Throwable.stackState fqn" should "be java.lang.Throwable.stackState" in {
    assert(JavaKnowledge.generateFieldFQN(new JawaType("java.lang.Throwable"), "stackState", new JawaType("int")).fqn == "java.lang.Throwable.stackState")
  }

  "java.lang.Throwable.stackState" should "get field name stackState" in {
    assert(JavaKnowledge.getFieldNameFromFieldFQN("java.lang.Throwable.stackState") == "stackState")
  }

  "java.lang.Throwable.stackState" should "have class Type JawaType(java.lang.Throwable)" in {
    assert(JavaKnowledge.getClassTypeFromFieldFQN("java.lang.Throwable.stackState") == new JawaType("java.lang.Throwable"))
  }

  "[Ljava.lang.String;.length" should "have class Type JawaType(java.lang.String, 1)" in {
    assert(JavaKnowledge.getClassTypeFromFieldFQN("[Ljava.lang.String;.length") == new JawaType("java.lang.String", 1))
  }
}
