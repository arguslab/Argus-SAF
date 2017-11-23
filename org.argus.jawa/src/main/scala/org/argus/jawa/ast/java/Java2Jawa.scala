/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.java

import com.github.javaparser.ast._
import com.github.javaparser.ast.expr._
import org.argus.jawa.ast.{AnnotationValue, StatementValue, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.Global
import org.argus.jawa.core.io.{JavaSourceFile, Position, RangePosition}
import org.argus.jawa.core.util._

class Java2Jawa(val global: Global, val sourceFile: JavaSourceFile) {

  protected[java] var packageName: String = ""

  protected[java] val imports: ImportHandler = new ImportHandler(this, sourceFile.getJavaCU.getImports)


  implicit class TransRange(node: Node) {
    def toRange: RangePosition = {
      val nodeRange = node.getRange
      if(nodeRange.isPresent) {
        val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line - 1) + nodeRange.get().begin.column - 1
        val endIn = sourceFile.lineToOffset(nodeRange.get().end.line - 1) + nodeRange.get().end.column - 1
        new RangePosition(sourceFile, startIn, endIn - startIn + 1, nodeRange.get().begin.line - 1, nodeRange.get().begin.column - 1)
      } else {
        new RangePosition(sourceFile, 0, 0, 0, 0)
      }
    }
  }

  implicit class StringProcess(str: String) {
    def apostrophe: String = s"`$str`"
    def doublequotes: String = "\"%s\"".format(str)
  }

  def process(resolveBody: Boolean): JawaCompilationUnit = {
    process(sourceFile.getJavaCU, resolveBody)
  }

  def process(cu: CompilationUnit, resolveBody: Boolean): JawaCompilationUnit = {
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    val topDecls: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    cu.getTypes.forEach{ typ =>
      val (i, is) = new ClassResolver(this, None, typ).process(resolveBody)
      topDecls ++= i :: is
    }
    val result = JawaCompilationUnit(topDecls.toList)(cu.toRange)
    result.topDecls foreach { cid =>
      val typ = cid.cityp
      cid.getAllChildrenInclude foreach (_.enclosingTopLevelClass = typ)
    }
    result
  }



  def processAnnotationExpr(ae: AnnotationExpr): JawaAnnotation = {
    val annoKey = Token(Tokens.ID, ae.getName.toRange, imports.findType(ae.getNameAsString, ae.getName.toRange).jawaName.apostrophe)
    val annoValue: Option[AnnotationValue] = ae match {
      case _: NormalAnnotationExpr =>
        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
      case _: SingleMemberAnnotationExpr =>
        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
      case _ => None // MarkerAnnotationExpr
    }
    JawaAnnotation(annoKey, annoValue)(ae.toRange)
  }

}

case class Java2JawaException(pos: Position, msg: String) extends RuntimeException(s"$pos: $msg")