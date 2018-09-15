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

import com.github.javaparser.JavaParser
import com.github.javaparser.ast.{CompilationUnit, NodeList}
import org.argus.jawa.ast.{CompilationUnit => JawaCompilationUnit}

import com.github.javaparser.ast.body.{BodyDeclaration, TypeDeclaration}
import org.argus.jawa.ast.javafile.Java2Jawa
import org.argus.jawa.core.{Global, JawaType, Reporter}
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.frontend.jawafile.JawaAstParser
import org.argus.jawa.core.io.{AbstractFile, DefaultSourceFile}
import org.argus.jawa.core.util.{IMap, ISet, MSet, msetEmpty}

class JavaSourceFile(global: Global, file: AbstractFile) extends DefaultSourceFile(file) {
  private var javacu: Option[CompilationUnit] = None

  def getJavaCU: CompilationUnit = {
    javacu match {
      case Some(cu) => cu
      case None =>
        val cu = JavaParser.parse(file.input)
        javacu = Some(cu)
        cu
    }
  }
  private def visitTypes(typ: JawaType, members: NodeList[BodyDeclaration[_ <: BodyDeclaration[_]]]): ISet[JawaType] = {
    val types: MSet[JawaType] = msetEmpty
    members.forEach {
      case td: TypeDeclaration[_] =>
        val innerTyp = new JawaType(s"${typ.jawaName}$$${td.getNameAsString}")
        types += innerTyp
        types ++= visitTypes(innerTyp, td.getMembers)
      case _ =>
    }
    types.toSet
  }
  def getTypes: ISet[JawaType] = {
    val types: MSet[JawaType] = msetEmpty
    val cu = getJavaCU
    var packageName = ""
    if(cu.getPackageDeclaration.isPresent) {
      packageName = cu.getPackageDeclaration.get().getName.asString() + "."
    }
    cu.getTypes.forEach{ typ =>
      val classType = new JawaType(s"$packageName${typ.getNameAsString}")
      types += classType
      types ++= visitTypes(classType, typ.getMembers)
    }
    types.toSet
  }

  private val j2j = new Java2Jawa(global, this)

  def parse(reporter: Reporter): IMap[JawaType, MyClass] = {
    val cids = j2j.process()
    cids.map { cid =>
      cid.typ -> JawaAstParser.resolveClass(cid)
    }.toMap
  }

  /**
    * Be aware this will parse method body
    */
  def getJawaCU: JawaCompilationUnit = {
    j2j.genCU()
  }
}