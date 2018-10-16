/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.jawafile

import org.argus.jawa.core.ast.MyClass
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{AbstractFile, DefaultSourceFile, Reporter}
import org.argus.jawa.core.util.{IMap, ISet}

class JawaSourceFile(file: AbstractFile) extends DefaultSourceFile(file) {
  def getClassCodes: ISet[String] = {
    val c = code
    c.replaceAll("(record `)", "DELIMITER_JAWA_HAHAHA$1").split("DELIMITER_JAWA_HAHAHA").tail.toSet
  }
  def parse(reporter: Reporter): IMap[JawaType, MyClass] = JawaAstParser.parse(this, reporter)
}