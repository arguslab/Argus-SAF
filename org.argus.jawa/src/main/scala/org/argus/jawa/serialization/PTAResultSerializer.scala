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

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.PTAResult.PTSMap
import org.argus.jawa.core.util._
import org.json4s._
import org.json4s.JsonDSL._

object PTAResultSerializer extends CustomSerializer[PTAResult](format => (
    {
      case jv: JValue =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer + ContextSerializer + ContextKeySerializer
        val pointsToMap = (jv \ "pointsToMap").extract[IMap[Context, PTSMap]]
        val pta_result = new PTAResult
        pta_result.addPointsToMap(pointsToMap)
        pta_result
    }, {
      case pta_result: PTAResult =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer + ContextSerializer + ContextKeySerializer
        "pointsToMap" -> Extraction.decompose(pta_result.pointsToMap)
    }
))
