/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.sourcefile

import org.argus.jawa.compiler.parser.{CompilationUnit, MethodDeclaration}
import org.argus.jawa.core.util._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class MyCUVisitor {
  private val classes: MMap[JawaType, MyClass] = mmapEmpty
  def getClasses: IMap[JawaType, MyClass] = classes.toMap
  
  /**
   * resolve all the classes, fields and procedures
   */
  def resolve(cu: CompilationUnit): Unit = {
    cu.topDecls foreach { cd =>
      val typ = cd.typ
      val accessFlag = AccessFlag.getAccessFlags(cd.accessModifier)
      val superType = cd.superClassOpt
      val interfaces = cd.interfaces
      var outerType: Option[JawaType] = None
      if(JavaKnowledge.isInnerClass(typ)) outerType = Some(JavaKnowledge.getOuterTypeFrom(typ))
      val myclass = MyClass(accessFlag, typ, superType, interfaces, outerType)
      this.classes(typ) = myclass
      cd.fields foreach { field =>
        val fieldType: JawaType = field.typ.typ
        val FQN: FieldFQN = new FieldFQN(field.FQN, fieldType)
        val accessFlag: Int = AccessFlag.getAccessFlags(field.accessModifier)
        val f = MyField(accessFlag, FQN)
        myclass.addField(f)
      }
      myclass.addField(createClassField(myclass))
      cd.methods foreach { method =>
        val m = resolveMethod(method)
        myclass.addMethod(m)
      }
    }
  }

  private def createClassField(rec: MyClass): MyField = {
    MyField(AccessFlag.getAccessFlags("FINAL_STATIC"), FieldFQN(rec.typ, "class", new JawaType("java.lang.Class")))
  }
  
  def resolveMethod(md: MethodDeclaration): MyMethod = {
    val signature = md.signature
    val accessFlag = AccessFlag.getAccessFlags(md.accessModifier)
    val m = MyMethod(accessFlag, signature, md.thisParam.map(_.name), md.paramList.map(_.name))
    m.setBody(md)
    m
  }
}
