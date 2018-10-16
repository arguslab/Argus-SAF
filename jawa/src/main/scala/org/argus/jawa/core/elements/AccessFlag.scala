/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.elements

import org.argus.jawa.core.util.{MList, mlistEmpty}
import org.objectweb.asm.Opcodes

/**
 * This object provides constants which represent jawa access flag; Some helper methods are also present.
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object AccessFlag{
  final private val ABSTRACT =              0x0001
  final private val FINAL =                 0x0002
  final private val INTERFACE =             0x0004
  final private val NATIVE =                0x0008
  final private val PRIVATE =               0x0010
  final private val PROTECTED =             0x0020
  final private val PUBLIC =                0x0040
  final private val STATIC =                0x0080
  final private val SYNCHRONIZED =          0x0100
  final private val TRANSIENT =             0x0200
  final private val VOLATILE =              0x0400
  final private val STRICTFP =              0x0800
  final private val ANNOTATION =            0x1000
  final private val ENUM =                  0x2000
  final private val SYNTHETIC =             0x4000
  final private val CONSTRUCTOR =           0x8000
  final private val DECLARED_SYNCHRONIZED = 0x10000

  def getAccessFlags(str: String): Int = {
    var af: Int = 0
    if(str.contains("ABSTRACT")) af = af | ABSTRACT
    if(str.contains("FINAL")) af = af | FINAL
    if(str.contains("INTERFACE")) af = af | INTERFACE
    if(str.contains("NATIVE")) af = af | NATIVE
    if(str.contains("PRIVATE")) af = af | PRIVATE
    else if(str.contains("PROTECTED")) af = af | PROTECTED
    else if(str.contains("PUBLIC")) af = af | PUBLIC
    if(str.contains("STATIC")) af = af | STATIC
    if(str.contains("TRANSIENT")) af = af | TRANSIENT
    if(str.contains("VOLATILE")) af = af | VOLATILE
    if(str.contains("STRICTFP")) af = af | STRICTFP
    if(str.contains("ANNOTATION")) af = af | ANNOTATION
    if(str.contains("ENUM")) af = af | ENUM
    if(str.contains("SYNTHETIC")) af = af | SYNTHETIC
    if(str.contains("CONSTRUCTOR")) af = af | CONSTRUCTOR
    if(str.contains("DECLARED_SYNCHRONIZED")) af = af | DECLARED_SYNCHRONIZED
    else if(str.contains("SYNCHRONIZED")) af = af | SYNCHRONIZED
    af
  }

  def getAccessFlagString(af: Int): String = {
    val flags: MList[String] = mlistEmpty
    if(isAbstract(af)) flags += "ABSTRACT"
    if(isFinal(af)) flags += "FINAL"
    if(isInterface(af)) flags += "INTERFACE"
    if(isNative(af)) flags += "NATIVE"
    if(isPrivate(af)) flags += "PRIVATE"
    else if(isProtected(af)) flags += "PROTECTED"
    else if(isPublic(af)) flags += "PUBLIC"
    if(isStatic(af)) flags += "STATIC"
    if(isTransient(af)) flags += "TRANSIENT"
    if(isVolatile(af)) flags += "VOLATILE"
    if(isStrictFP(af)) flags += "STRICTFP"
    if(isAnnotation(af)) flags += "ANNOTATION"
    if(isEnum(af)) flags += "ENUM"
    if(isSynthetic(af)) flags += "SYNTHETIC"
    if(isConstructor(af)) flags += "CONSTRUCTOR"
    if(isDeclaredSynchronized(af)) flags += "DECLARED_SYNCHRONIZED"
    else if(isSynchronized(af)) flags += "SYNCHRONIZED"
    flags.mkString("_")
  }

  def isAbstract(af: Int): Boolean = (af & ABSTRACT) != 0
  def isFinal(af: Int): Boolean = (af & FINAL) != 0
  def isInterface(af: Int): Boolean = (af & INTERFACE) != 0
  def isNative(af: Int): Boolean = (af & NATIVE) != 0
  def isPrivate(af: Int): Boolean = (af & PRIVATE) != 0
  def isProtected(af: Int): Boolean = (af & PROTECTED) != 0
  def isPublic(af: Int): Boolean = (af & PUBLIC) != 0
  def isStatic(af: Int): Boolean = (af & STATIC) != 0
  def isSynchronized(af: Int): Boolean = (af & SYNCHRONIZED) != 0
  def isTransient(af: Int): Boolean = (af & TRANSIENT) != 0
  def isVolatile(af: Int): Boolean = (af & VOLATILE) != 0
  def isStrictFP(af: Int): Boolean = (af & STRICTFP) != 0
  def isAnnotation(af: Int): Boolean = (af & ANNOTATION) != 0
  def isEnum(af: Int): Boolean = (af & ENUM) != 0
  def isSynthetic(af: Int): Boolean = (af & SYNTHETIC) != 0
  def isConstructor(af: Int): Boolean = (af & CONSTRUCTOR) != 0
  def isDeclaredSynchronized(af: Int): Boolean = (af & DECLARED_SYNCHRONIZED) != 0

  def getJavaFlags(af: Int): Int = {
    var mod: Int = 0
    if(isPrivate(af))
      mod = mod | Opcodes.ACC_PRIVATE
    else if (isProtected(af))
      mod = mod | Opcodes.ACC_PROTECTED
    else if (isPublic(af))
      mod = mod | Opcodes.ACC_PUBLIC

    if(isAbstract(af))
      mod = mod | Opcodes.ACC_ABSTRACT
    if(isAnnotation(af))
      mod = mod | Opcodes.ACC_ANNOTATION
//    if(isConstructor(af))
//      mod = mod | Opcodes.ACC_
    if(isDeclaredSynchronized(af))
      mod = mod | Opcodes.ACC_SYNCHRONIZED
    if(isEnum(af))
      mod = mod | Opcodes.ACC_ENUM
    if(isFinal(af))
      mod = mod | Opcodes.ACC_FINAL
    if(isInterface(af))
      mod = mod | Opcodes.ACC_INTERFACE
    if(isNative(af))
      mod = mod | Opcodes.ACC_NATIVE
    if(isStatic(af))
      mod = mod | Opcodes.ACC_STATIC
    if(isStrictFP(af))
      mod = mod | Opcodes.ACC_STRICT
    if(isSynchronized(af))
      mod = mod | Opcodes.ACC_SYNCHRONIZED
    if(isSynthetic(af))
      mod = mod | Opcodes.ACC_SYNTHETIC
    if(isTransient(af))
      mod = mod | Opcodes.ACC_TRANSIENT
    if(isVolatile(af))
      mod = mod | Opcodes.ACC_VOLATILE
    mod
  }

  object FlagKind extends Enumeration {
    val CLASS, FIELD, METHOD = Value
  }

  def getJawaFlags(jf: Int, kind: FlagKind.Value, isConstructor: Boolean): Int = {
    var mod: Int = 0
    if(isConstructor)
      mod = mod | CONSTRUCTOR
    if((jf & Opcodes.ACC_PRIVATE) != 0)
      mod = mod | PRIVATE
    else if ((jf & Opcodes.ACC_PROTECTED) != 0)
      mod = mod | PROTECTED
    else if ((jf & Opcodes.ACC_PUBLIC) != 0)
      mod = mod | PUBLIC

    kind match {
      case FlagKind.METHOD =>
        if((jf & Opcodes.ACC_SYNCHRONIZED) != 0)
          mod = mod | SYNCHRONIZED
      case FlagKind.FIELD =>
        if((jf & Opcodes.ACC_VOLATILE) != 0)
          mod = mod | VOLATILE
        if((jf & Opcodes.ACC_TRANSIENT) != 0)
          mod = mod | TRANSIENT
      case _ =>
    }

    if((jf & Opcodes.ACC_ABSTRACT) != 0)
      mod = mod | ABSTRACT
    if((jf & Opcodes.ACC_ANNOTATION) != 0)
      mod = mod | ANNOTATION
//    if(isConstructor(af))
//      mod = mod | Opcodes.ACC_
    if((jf & Opcodes.ACC_ENUM) != 0)
      mod = mod | ENUM
    if((jf & Opcodes.ACC_FINAL) != 0)
      mod = mod | FINAL
    if((jf & Opcodes.ACC_INTERFACE) != 0)
      mod = mod | INTERFACE
    if((jf & Opcodes.ACC_NATIVE) != 0)
      mod = mod | NATIVE
    if((jf & Opcodes.ACC_STATIC) != 0)
      mod = mod | STATIC
    if((jf & Opcodes.ACC_STRICT) != 0)
      mod = mod | STRICTFP
    if((jf & Opcodes.ACC_SYNTHETIC) != 0)
      mod = mod | SYNTHETIC
    mod
  }

  def toString(af: Int): String = {
    val sb = new StringBuffer
    if(isPublic(af)) sb.append("public ")
    else if(isPrivate(af)) sb.append("private ")
    else if(isProtected(af)) sb.append("protected ")
    if(isAbstract(af)) sb.append("abstract ")
    if(isStatic(af)) sb.append("static ")
    if(isFinal(af)) sb.append("final ")
    if(isSynchronized(af)) sb.append("synchronized ")
    if(isNative(af)) sb.append("native ")
    if(isTransient(af)) sb.append("transient ")
    if(isVolatile(af)) sb.append("volatile ")
    if(isStrictFP(af)) sb.append("strictfp ")
    if(isAnnotation(af)) sb.append("annotation ")
    if(isEnum(af)) sb.append("enum ")
    if(isSynthetic(af)) sb.append("synthetic ")
    if(isConstructor(af)) sb.append("constructor ")
    if(isDeclaredSynchronized(af)) sb.append("declared_synchronized ")
    if(isInterface(af)) sb.append("interface ")
    sb.toString.trim()
  }
}
