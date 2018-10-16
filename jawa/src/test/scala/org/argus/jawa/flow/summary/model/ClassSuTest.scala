/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.model

import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/21/17.
  */
class ClassSuTest extends SuTestBase("Class.safsu") {

  val thisInstance = PTAInstance(JavaKnowledge.CLASS, defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisNameFact = RFAFact(FieldSlot(thisInstance, "name"), PTAConcreteStringInstance("my.Class", defContext))

  "Ljava/lang/Class;.asSubclass:(Ljava/lang/Class;)Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.SubClass", defContext2))
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.SubClass", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, defContext2))
  )

  "Ljava/lang/Class;.cast:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.SubClass", defContext2))
  ) produce (
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.SubClass", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, defContext2))
  )

  "Ljava/lang/Class;.desiredAssertionStatus:()Z" with_input () produce ()

  "Ljava/lang/Class;.forName:(Ljava/lang/String;)Ljava/lang/Class;" with_input RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.SubClass", defContext2)) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.SubClass", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAConcreteStringInstance("my.SubClass", defContext2))
  )

  "Ljava/lang/Class;.forName:(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;" with_input RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.SubClass", defContext2)) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.SubClass", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAConcreteStringInstance("my.SubClass", defContext2))
  )

  "Ljava/lang/Class;.getAnnotation:(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;" with_input (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Annotation", defContext2))
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Annotation", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.annotation.Annotation").toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getAnnotations:()[Ljava/lang/annotation/Annotation;" with_input (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Annotation", defContext2))
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("v1"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Annotation", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.annotation.Annotation", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.annotation.Annotation", 1), currentContext)), PTAInstance(new JawaType("java.lang.annotation.Annotation").toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getCanonicalName:()Ljava/lang/String;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("my.Class", defContext))
  )

  "Ljava/lang/Class;.getClassLoader:()Ljava/lang/ClassLoader;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.ClassLoader").toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getClasses:()[Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Class", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Class", 1), currentContext)), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getComponentType:()Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getConstructor:([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext))
  )

  "Ljava/lang/Class;.getConstructors:()[Ljava/lang/reflect/Constructor;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Constructor", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredAnnotations:()[Ljava/lang/annotation/Annotation;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.annotation.Annotation", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.annotation.Annotation", 1), currentContext)), PTAInstance(new JawaType("java.lang.annotation.Annotation"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredClasses:()[Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Class", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Class", 1), currentContext)), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getDeclaredConstructor:([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredConstructorOrMethod:(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Member;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredConstructors:()[Ljava/lang/reflect/Constructor;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Constructor", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredField:(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredField:(Ljava/lang/String;)Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredFields:()[Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredFields:(Ljava/lang/Class;Z)[Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredMethods:()[Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaredMethods:(Ljava/lang/Class;Z)[Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getDeclaringClass:()Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getEnclosingClass:()Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getEnclosingConstructor:()Ljava/lang/reflect/Constructor;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Constructor"), currentContext))
  )

  "Ljava/lang/Class;.getEnclosingMethod:()Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getEnumConstants:()[Ljava/lang/Object;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JawaType.addDimensions(JavaKnowledge.OBJECT, 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(JawaType.addDimensions(JavaKnowledge.OBJECT, 1), currentContext)), PTAInstance(JavaKnowledge.OBJECT.toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getField:(Ljava/lang/String;)Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getFields:()[Ljava/lang/reflect/Field;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Field", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Field"), currentContext))
  )

  "Ljava/lang/Class;.getGenericInterfaces:()[Ljava/lang/reflect/Type;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Type", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Type", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Type"), currentContext))
  )

  "Ljava/lang/Class;.getGenericSuperclass:()Ljava/lang/reflect/Type;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Type"), currentContext))
  )

  "Ljava/lang/Class;.getInterfaces:()[Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Class", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Class", 1), currentContext)), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getMethods:()[Ljava/lang/reflect/Method;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.Method", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.Method"), currentContext))
  )

  "Ljava/lang/Class;.getModifiers:()I" with_input () produce ()

  "Ljava/lang/Class;.getName:()Ljava/lang/String;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("my.Class", defContext))
  )

  "Ljava/lang/Class;.getPackage:()Ljava/lang/Package;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Package"), currentContext))
  )

  "Ljava/lang/Class;.getProtectionDomain:()Ljava/security/ProtectionDomain;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.security.ProtectionDomain"), currentContext))
  )

  "Ljava/lang/Class;.getResource:(Ljava/lang/String;)Ljava/net/URL;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.net.URL"), currentContext))
  )

  "Ljava/lang/Class;.getResourceAsStream:(Ljava/lang/String;)Ljava/io/InputStream;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.io.InputStream").toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getSigners:()[Ljava/lang/Object;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JawaType.addDimensions(JavaKnowledge.OBJECT, 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(JawaType.addDimensions(JavaKnowledge.OBJECT, 1), currentContext)), PTAInstance(JavaKnowledge.OBJECT.toUnknown, currentContext))
  )

  "Ljava/lang/Class;.getSimpleName:()Ljava/lang/String;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("my.Class", defContext))
  )

  "Ljava/lang/Class;.getSuperclass:()Ljava/lang/Class;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Class;.getTypeParameters:()[Ljava/lang/reflect/TypeVariable;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.reflect.TypeVariable", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.reflect.TypeVariable", 1), currentContext)), PTAInstance(new JawaType("java.lang.reflect.TypeVariable"), currentContext))
  )

  "Ljava/lang/Class;.isAnnotation:()Z" with_input () produce ()

  "Ljava/lang/Class;.isAnnotationPresent:(Ljava/lang/Class;)Z" with_input () produce ()

  "Ljava/lang/Class;.isAnonymousClass:()Z" with_input () produce ()

  "Ljava/lang/Class;.isArray:()Z" with_input () produce ()

  "Ljava/lang/Class;.isAssignableFrom:(Ljava/lang/Class;)Z" with_input () produce ()

  "Ljava/lang/Class;.isEnum:()Z" with_input () produce ()

  "Ljava/lang/Class;.isInstance:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/lang/Class;.isInterface:()Z" with_input () produce ()

  "Ljava/lang/Class;.isLocalClass:()Z" with_input () produce ()

  "Ljava/lang/Class;.isMemberClass:()Z" with_input () produce ()

  "Ljava/lang/Class;.isPrimitive:()Z" with_input () produce ()

  "Ljava/lang/Class;.isSynthetic:()Z" with_input () produce ()

  "Ljava/lang/Class;.newInstance:()Ljava/lang/Object;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.OBJECT.toUnknown, currentContext))
  )

  "Ljava/lang/Class;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisNameFact
  ) produce (
    thisFact,
    thisNameFact,
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("my.Class", defContext))
  )
}
