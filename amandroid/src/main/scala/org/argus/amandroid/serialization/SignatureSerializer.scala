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

import org.argus.jawa.core.elements.Signature
import org.json4s._
import org.json4s.JsonDSL._

object SignatureSerializer extends CustomSerializer[Signature](format => (
    {
      case jv: JValue =>
        implicit val formats: DefaultFormats.type = DefaultFormats
        val str = (jv \ "sig").extract[String]
        new Signature(str)
    },
    {
      case sig: Signature =>
        "sig" -> sig.signature
    }
))

object SignatureKeySerializer extends CustomKeySerializer[Signature](format => (
    {
      case str: String =>
        new Signature(str)
    },
    {
      case sig: Signature =>
        sig.signature
    }
))