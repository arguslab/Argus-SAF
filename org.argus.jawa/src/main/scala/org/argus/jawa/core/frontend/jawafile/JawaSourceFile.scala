/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.frontend.jawafile

import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.io.{AbstractFile, DefaultSourceFile}
import org.argus.jawa.core.util.{IMap, ISet}
import org.argus.jawa.core.{JawaType, Reporter}

class JawaSourceFile(file: AbstractFile) extends DefaultSourceFile(file) {
  def getClassCodes: ISet[String] = {
    val c = code
    c.replaceAll("(record `)", "DELIMITER_JAWA_HAHAHA$1").split("DELIMITER_JAWA_HAHAHA").tail.toSet
  }
  def parse(reporter: Reporter): IMap[JawaType, MyClass] = JawaAstParser.parse(this, reporter)
}