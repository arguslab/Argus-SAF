/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.pilarCodeGenerator

import org.argus.jawa.core.JawaType
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class VariableGenerator {
  private val varMap: MMap[String, Int] = mmapEmpty
  def generate(typ: JawaType): String = {
    var variable: String = ""
    typ.name match {
      case "int" => 
        if(varMap.contains("int")) varMap("int") += 1
        else varMap.put("int", 0)
        variable = "i" + varMap("int")
      case "boolean" => 
        if(varMap.contains("boolean")) varMap("boolean") += 1
        else varMap.put("boolean", 0)
        variable = "z" + varMap("boolean")
      case _ => 
        if(varMap.contains("object")) varMap("object") += 1
        else varMap.put("object", 0)
        variable = "r" + varMap("object")
    }
    variable
  }
}
