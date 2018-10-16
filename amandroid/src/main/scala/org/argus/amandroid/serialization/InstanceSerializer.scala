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

import org.argus.jawa.flow.pta._
import org.json4s._
import org.json4s.JsonDSL._

object InstanceSerializer extends CustomSerializer[Instance](format => (
    {
      case jv: JValue =>
        implicit val formats: Formats = format + ContextSerializer + JawaTypeSerializer
        jv match {
          case JObject(List(JField("PTAInstance", v))) => Extraction.extract[PTAInstance](v)
          case JObject(List(JField("PTAPointStringInstance", v))) => Extraction.extract[PTAPointStringInstance](v)
          case JObject(List(JField("PTAConcreteStringInstance", v))) => Extraction.extract[PTAConcreteStringInstance](v)
        }
    }, {
      case ins: Instance =>
        implicit val formats: Formats = format + ContextSerializer + JawaTypeSerializer
        ins match {
          case c: PTAInstance => "PTAInstance" -> ("typ" -> Extraction.decompose(c.typ)) ~ ("defSite" -> Extraction.decompose(c.defSite))
          case c: PTAPointStringInstance => "PTAPointStringInstance" -> ("defSite" -> Extraction.decompose(c.defSite))
          case c: PTAConcreteStringInstance => "PTAConcreteStringInstance" -> ("string" -> c.string) ~ ("defSite" -> Extraction.decompose(c.defSite))
        }
    }
))
