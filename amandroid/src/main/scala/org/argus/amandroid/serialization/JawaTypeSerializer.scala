/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.json4s._
import org.json4s.JsonDSL._

object JawaTypeSerializer extends CustomSerializer[JawaType](format => (
    {
      case jv: JValue =>
        implicit val formats: Formats = format
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
