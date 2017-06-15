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

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.PTAResult.PTSMap
import org.json4s._
import org.json4s.JsonDSL._
import org.argus.jawa.core.util._

object PTAResultSerializer extends CustomSerializer[PTAResult](format => (
    {
      case jv: JValue =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer + ContextSerializer + ContextKeySerializer
        val beforePointsToMap = (jv \ "beforePointsToMap").extract[IMap[Context, PTSMap]]
        val afterPointsToMap = (jv \ "afterPointsToMap").extract[IMap[Context, PTSMap]]
        val pta_result = new PTAResult
        pta_result.addPointsToMap(after = false, beforePointsToMap)
        pta_result.addPointsToMap(after = false, afterPointsToMap)
        pta_result
    }, {
      case pta_result: PTAResult =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer + ContextSerializer + ContextKeySerializer
        ("beforePointsToMap" -> Extraction.decompose(pta_result.pointsToMap(after = false))) ~
        ("afterPointsToMap" -> Extraction.decompose(pta_result.pointsToMap(after = true)))
    }
))
