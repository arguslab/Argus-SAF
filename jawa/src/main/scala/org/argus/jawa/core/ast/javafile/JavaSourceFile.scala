/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.javafile

import com.github.javaparser.JavaParser
import com.github.javaparser.ast.body.{BodyDeclaration, TypeDeclaration}
import com.github.javaparser.ast.{CompilationUnit, NodeList}
import org.argus.jawa.core.Global
import org.argus.jawa.core.ast.{MyClass, CompilationUnit => JawaCompilationUnit}
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{AbstractFile, DefaultSourceFile, Reporter}
import org.argus.jawa.core.ast.jawafile.JawaAstParser
import org.argus.jawa.core.util.{IMap, ISet, MSet, msetEmpty}
import scala.collection.JavaConverters._

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
    members.asScala.foreach {
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
    cu.getTypes.asScala.foreach { typ =>
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