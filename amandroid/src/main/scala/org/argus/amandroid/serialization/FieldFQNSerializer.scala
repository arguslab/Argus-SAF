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

import org.argus.jawa.core.JawaType
import org.argus.jawa.core.elements.FieldFQN
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