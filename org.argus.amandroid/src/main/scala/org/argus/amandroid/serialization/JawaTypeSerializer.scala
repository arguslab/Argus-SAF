/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.jawa.core.{JavaKnowledge, JawaType}
import org.json4s._
import org.json4s.JsonDSL._

object JawaTypeSerializer extends CustomSerializer[JawaType](format => (
    {
      case jv: JValue =>
        implicit val formats = format
        val str = (jv \ "typ").extract[String]
        JavaKnowledge.getTypeFromJawaName(str)
    },
    {
      case typ: JawaType =>
        "typ" -> typ.jawaName
    }
))

object JawaTypeKeySerializer extends CustomKeySerializer[JawaType](_ => (
    {
      case str: String =>
        JavaKnowledge.getTypeFromJawaName(str)
    }, {
      case typ: JawaType =>
        typ.jawaName
    }
))
