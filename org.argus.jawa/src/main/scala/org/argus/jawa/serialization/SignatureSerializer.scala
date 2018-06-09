/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.serialization

import org.argus.jawa.core.Signature
import org.json4s.JsonDSL._
import org.json4s.{CustomKeySerializer, CustomSerializer, DefaultFormats, JValue}

object SignatureSerializer extends CustomSerializer[Signature](_ => (
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

object SignatureKeySerializer extends CustomKeySerializer[Signature](_ => (
    {
      case str: String =>
        new Signature(str)
    },
    {
      case sig: Signature =>
        sig.signature
    }
))