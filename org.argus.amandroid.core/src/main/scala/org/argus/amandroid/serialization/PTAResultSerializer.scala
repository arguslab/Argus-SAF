/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.PTAResult.PTSMap
import org.argus.jawa.core.Signature
import org.json4s._
import org.json4s.JsonDSL._
import org.sireum.util._

object PTAResultSerializer extends CustomSerializer[PTAResult](format => (
    {
      case jv: JValue =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer
        val entryPoints = (jv \ "entryPoints").extract[ISet[Signature]]
        val pointsToMap = (jv \ "pointsToMap").extract[IMap[String, PTSMap]]
        val ptaresult = new PTAResult
        ptaresult.addEntryPoints(entryPoints)
        ptaresult.addPointsToMap(pointsToMap)
        ptaresult
    }, {
      case ptaresult: PTAResult =>
        implicit val formats = format + PTASlotKeySerializer + InstanceSerializer + SignatureSerializer
        ("entryPoints" -> Extraction.decompose(ptaresult.getEntryPoints)) ~
        ("pointsToMap" -> Extraction.decompose(ptaresult.pointsToMap))
    }
))
