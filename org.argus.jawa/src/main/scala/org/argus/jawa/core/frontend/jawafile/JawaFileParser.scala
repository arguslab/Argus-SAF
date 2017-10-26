/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.frontend.jawafile

import org.argus.jawa.ast.{CompilationUnit, MethodDeclaration}
import org.argus.jawa.core.io.SourceFile
import org.argus.jawa.core._
import org.argus.jawa.core.frontend.{MyClass, MyField, MyMethod}
import org.argus.jawa.core.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object JawaFileParser {
  final val TITLE = "JawaFileParser"
  final val debug = false
  def parse(file: SourceFile, reporter: Reporter): IMap[JawaType, MyClass] = {
    parse(file.code, reporter)
  }
  def parse(code: String, reporter: Reporter): IMap[JawaType, MyClass] = {
    try {
      val cu: CompilationUnit = JawaResolver.parseClass(code.replaceAllLiterally("#. ", "# "), reporter)
      resolve(cu)
    } catch {
      case e: Exception =>
        reporter.error(TITLE, e.getMessage)
        reporter.error(TITLE, code)
        if(debug) {
          e.printStackTrace()
        }
        imapEmpty
    }
  }

  /**
    * resolve all the classes, fields and procedures
    */
  def resolve(cu: CompilationUnit): IMap[JawaType, MyClass] = {
    val classes: MMap[JawaType, MyClass] = mmapEmpty
    cu.topDecls foreach { cd =>
      val typ = cd.typ
      val accessFlag = AccessFlag.getAccessFlags(cd.accessModifier)
      val superType = cd.superClassOpt match {
        case Some(a) => Some(a)
        case None =>
          if(typ != JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE) Some(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
          else None
      }
      val interfaces = cd.interfaces
      var outerType: Option[JawaType] = None
      if(JavaKnowledge.isInnerClass(typ)) outerType = Some(JavaKnowledge.getOuterTypeFrom(typ))
      val myclass = MyClass(accessFlag, typ, superType, interfaces, outerType)
      classes(typ) = myclass
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
    classes.toMap
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
