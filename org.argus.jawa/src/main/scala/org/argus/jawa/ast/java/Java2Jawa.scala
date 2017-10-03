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

import com.github.javaparser.JavaParser
import com.github.javaparser.ast.{CompilationUnit, Node}
import com.github.javaparser.ast.body.{AnnotationDeclaration, ClassOrInterfaceDeclaration, EnumDeclaration, TypeDeclaration}
import org.argus.jawa.ast.{TypeDefSymbol, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit}
import org.argus.jawa.compiler.lexer.{Token, TokenType}
import org.argus.jawa.core.io.{JavaSourceFile, RangePosition}

class Java2Jawa {

  var packageName: String = ""

//  implicit class TransToken(node: Node) {
//    def toToken(typ: TokenType): Token = {
//      val nodeRange = node.getRange
//      nodeRange
//      val range: RangePosition = new RangePosition()
//      Token(typ, )
//    }
//  }

  def process(sourceFile: JavaSourceFile): JawaCompilationUnit = {
    val cu = JavaParser.parse(sourceFile.code)
    process(cu)
  }

  def process(cu: CompilationUnit): JawaCompilationUnit = {
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    cu.getTypes.forEach(typ => process(typ))
    println(packageName)
    null
  }

  def process(typ: TypeDeclaration[_]): JawaClassOrInterfaceDeclaration = {
    typ match {
      case cid: ClassOrInterfaceDeclaration =>
//        cid.getName
//        val cityp: TypeDefSymbol =
//        annotations: IList[Annotation],
//        extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses],
//        instanceFieldDeclarationBlock: InstanceFieldDeclarationBlock,
//        staticFields: IList[StaticFieldDeclaration],
//        methods: IList[MethodDeclaration]
//        JawaClassOrInterfaceDeclaration(null, )
      case ed: EnumDeclaration =>
      case ad: AnnotationDeclaration =>
    }
    println(typ.getClass)
    null
  }
}
