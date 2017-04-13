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

import org.argus.jawa.core.io.SourceFile
import org.argus.jawa.core._
import org.sireum.pilar.symbol.SymbolTable
import org.sireum.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object SourcefileParser {
  final val TITLE = "SourcefileParser"
  final val debug = false
  def parse(file: SourceFile, level: ResolveLevel.Value, reporter: Reporter): IMap[JawaType, MyClass] = {
    parse(file.code, level, reporter)
  }
  def parse(str: String, level: ResolveLevel.Value, reporter: Reporter): IMap[JawaType, MyClass] = {
    var code = str
    if(level < ResolveLevel.BODY) {
      code = LightWeightPilarParser.getEmptyBodyCode(code)
    }
    val v = new MySTVisitor
    try {
      val st: SymbolTable = JawaResolver.getSymbolResolveResult(Set(code.replaceAllLiterally("#. ", "# ")))
      v.resolveFromST(st, level)
    } catch {
      case ie: InterruptedException => throw ie
      case e: Exception =>
        reporter.error(TITLE, e.getMessage)
        reporter.error(TITLE, code)
        if(debug) {
          e.printStackTrace()
        }
    }
    v.getClasses
  }
}
