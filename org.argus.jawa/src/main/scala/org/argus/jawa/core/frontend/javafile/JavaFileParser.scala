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

import org.argus.jawa.ast.java.Java2Jawa
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.frontend.jawafile.JawaFileParser
import org.argus.jawa.core.io.JavaSourceFile
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaType, Reporter}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object JavaFileParser {
  final val TITLE = "JavaFileParser"
  final val debug = true
  def parse(global: Global, file: JavaSourceFile, reporter: Reporter): IMap[JawaType, MyClass] = {
    val j2j = new Java2Jawa(global, file)
    JawaFileParser.resolve(j2j.process(false))
  }
}
