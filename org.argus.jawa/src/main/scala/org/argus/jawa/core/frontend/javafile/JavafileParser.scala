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
import org.argus.jawa.core.{JawaType, Reporter}
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.io.SourceFile
import org.argus.jawa.core.util._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object JavafileParser {
  final val TITLE = "JavafileParser"
  final val debug = true
  def parse(file: SourceFile, reporter: Reporter): IMap[JawaType, MyClass] = {
    val cu = JavaParser.parse(file.code)
    val mjv = new MyJavaVisitor
    cu.accept(mjv, null)
    mjv.getClasses
  }
}
