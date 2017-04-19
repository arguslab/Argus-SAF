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

import org.argus.jawa.compiler.parser.CompilationUnit
import org.argus.jawa.core.io.SourceFile
import org.argus.jawa.core._
import org.argus.jawa.core.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object SourcefileParser {
  final val TITLE = "SourcefileParser"
  final val debug = true
  def parse(file: SourceFile, reporter: Reporter): IMap[JawaType, MyClass] = {
    parse(file.code, reporter)
  }
  def parse(code: String, reporter: Reporter): IMap[JawaType, MyClass] = {
    val v = new MyCUVisitor
    try {
      val cu: CompilationUnit = JawaResolver.parseClass(code.replaceAllLiterally("#. ", "# "), reporter)
      v.resolve(cu)
    } catch {
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
