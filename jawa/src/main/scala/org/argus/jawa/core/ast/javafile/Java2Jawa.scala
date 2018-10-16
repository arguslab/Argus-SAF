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

import com.github.javaparser.ast._
import org.argus.jawa.core.ast.{ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit}
import org.argus.jawa.core.Global
import org.argus.jawa.core.io.{Position, RangePosition}
import org.argus.jawa.core.util._

class Java2Jawa(val global: Global, val sourceFile: JavaSourceFile) {

  protected[javafile] var packageName: String = ""

//  protected[javafile] val imports: ImportHandler = new ImportHandler(this, sourceFile.getJavaCU.getImports)

  protected[javafile] val topDecls: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty

  implicit class TransRange(node: Node) {
    def toRange: RangePosition = {
      val nodeRange = node.getRange
      if(nodeRange.isPresent) {
        val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line - 1) + nodeRange.get().begin.column - 1
        val endIn = sourceFile.lineToOffset(nodeRange.get().end.line - 1) + nodeRange.get().end.column - 1
        new RangePosition(sourceFile, startIn, endIn - startIn + 1)
      } else {
        new RangePosition(sourceFile, 0, 0)
      }
    }
  }

  implicit class StringProcess(str: String) {
    def apostrophe: String = s"`$str`"
    def doublequotes: String = "\"%s\"".format(str)
  }

  def process(): IList[JawaClassOrInterfaceDeclaration] = {
    if(topDecls.isEmpty) {
      process(sourceFile.getJavaCU)
    }
    topDecls.toList
  }

  def genCU(): JawaCompilationUnit = {
    val cids = process()
    cids.foreach { cid =>
      cid.methods.foreach { md =>
        md.resolvedBody
      }
    }
    JawaCompilationUnit(topDecls.toList)(sourceFile.getJavaCU.toRange)
  }

  def process(cu: CompilationUnit): Unit = {
//    imports.processImports()
//    val pd = cu.getPackageDeclaration
//    if(pd.isPresent) {
//      packageName = pd.get().getName.asString()
//    }
//    cu.getTypes.forEach{ typ =>
//      new ClassResolver(this, None, 0, typ, false, None, false).process()
//    }
  }



//  def processAnnotationExpr(ae: AnnotationExpr): JawaAnnotation = {
//    val annoKey = Token(Tokens.ID, ae.getName.toRange, imports.findType(ae.getNameAsString, ae.getName.toRange).jawaName.apostrophe)
//    val annoValue: Option[AnnotationValue] = ae match {
//      case _: NormalAnnotationExpr =>
//        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
//      case _: SingleMemberAnnotationExpr =>
//        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
//      case _ => None // MarkerAnnotationExpr
//    }
//    JawaAnnotation(annoKey, annoValue)(ae.toRange)
//  }

}

case class Java2JawaException(pos: Position, msg: String) extends RuntimeException(s"$pos: $msg")