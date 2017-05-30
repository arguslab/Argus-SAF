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

import org.argus.jawa.alir.pta._
import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.native.JsonMethods._

object PTASlotKeySerializer extends CustomKeySerializer[PTASlot](format => (
    {
      case str: String =>
        implicit val formats = format + InstanceSerializer + SignatureSerializer + JawaTypeSerializer + FieldFQNSerializer
        val jv = parse(str)
        jv match {
          case JObject(List(JField("VarSlot", v))) => Extraction.extract[VarSlot](v)
          case JObject(List(JField("StaticFieldSlot", v))) => Extraction.extract[StaticFieldSlot](v)
          case JObject(List(JField("FieldSlot", v))) => Extraction.extract[FieldSlot](v)
          case JObject(List(JField("ArraySlot", v))) => Extraction.extract[ArraySlot](v)
          case JObject(List(JField("InstanceSlot", v))) => Extraction.extract[InstanceSlot](v)
          case JObject(List(JField("InvokeSlot", v))) => Extraction.extract[InvokeSlot](v)
        }
    }, {
      case slot: PTASlot =>
        implicit val formats = format + InstanceSerializer + SignatureSerializer + JawaTypeSerializer + FieldFQNSerializer
        slot match {
          case s: VarSlot =>
            compact(render("VarSlot" -> Extraction.decompose(s)))
          case s: StaticFieldSlot =>
            compact(render("StaticFieldSlot" -> Extraction.decompose(s)))
          case s: FieldSlot =>
            compact(render("FieldSlot" -> ("ins" -> Extraction.decompose(s.ins)) ~ ("fieldName" -> Extraction.decompose(s.fieldName))))
          case s: ArraySlot =>
            compact(render("ArraySlot" -> ("ins" -> Extraction.decompose(s.ins))))
          case s: InstanceSlot =>
            compact(render("InstanceSlot" -> ("ins" -> Extraction.decompose(s.ins))))
          case s: InvokeSlot =>
            compact(render("InvokeSlot" -> Extraction.decompose(s)))
        }
    }
))
