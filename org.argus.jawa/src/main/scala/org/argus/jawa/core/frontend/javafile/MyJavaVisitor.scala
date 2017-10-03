/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.frontend.javafile

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration
import com.github.javaparser.ast.visitor.VoidVisitorAdapter
import org.argus.jawa.core.JawaType
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.util.{IMap, MMap, mmapEmpty}

class MyJavaVisitor extends VoidVisitorAdapter[Void] {
  private val classes: MMap[JawaType, MyClass] = mmapEmpty
  private var currentClass: MyClass = _
  def getClasses: IMap[JawaType, MyClass] = classes.toMap

  override def visit(ci: ClassOrInterfaceDeclaration, arg: Void): Unit = {
    println(ci.getName)
    println(ci.getModifiers)
    println(ci.getExtendedTypes)
    println(ci.getImplementedTypes)
  }
}
