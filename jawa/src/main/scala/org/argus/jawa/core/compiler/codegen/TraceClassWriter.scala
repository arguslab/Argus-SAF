/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.codegen

import org.argus.jawa.core.Global
import org.argus.jawa.core.elements.JavaKnowledge
import org.objectweb.asm.ClassWriter

/**
  * Created by fgwei on 5/1/17.
  */
class TraceClassWriter(flags: Int, global: Global) extends ClassWriter(flags) {
  override def getCommonSuperClass(type1: String, type2: String): String = {
    var c = global.getClassOrResolve(JavaKnowledge.getTypeFromName(type1.replace('/', '.')))
    val d = global.getClassOrResolve(JavaKnowledge.getTypeFromName(type2.replace('/', '.')))
    if(c.isAssignableFrom(d)) return type1
    if(d.isAssignableFrom(c)) return type2
    if(c.isInterface || d.isInterface) "java/lang/Object"
    else {
      do c = c.getSuperClass
      while (!c.isAssignableFrom(d))
      c.getName.replace('.', '/')
    }
  }
}
