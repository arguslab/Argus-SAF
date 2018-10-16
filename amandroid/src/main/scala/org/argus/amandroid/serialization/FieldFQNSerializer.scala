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

import org.argus.jawa.core.elements.{FieldFQN, JawaType}
import org.json4s._
import org.json4s.JsonDSL._

/**
  * Created by fgwei on 4/22/17.
  */
object FieldFQNSerializer extends CustomSerializer[FieldFQN](format => (
  {
    case jv: JValue =>
      implicit val formats: Formats = format + JawaTypeSerializer
      val owner = (jv \ "owner").extract[JawaType]
      val fieldName = (jv \ "fieldName").extract[String]
      val typ = (jv \ "typ").extract[JawaType]
      new FieldFQN(owner, fieldName, typ)
  },
  {
    case fqn: FieldFQN =>
      implicit val formats: Formats = format + JawaTypeSerializer
      ("owner" -> Extraction.decompose(fqn.owner)) ~
      ("fieldName" -> fqn.fieldName) ~
      ("typ" -> Extraction.decompose(fqn.typ))
  }
))