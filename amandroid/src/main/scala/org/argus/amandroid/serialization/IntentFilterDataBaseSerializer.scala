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

import org.argus.amandroid.core.parser.{Authority, Data, IntentFilter, IntentFilterDataBase}
import org.argus.jawa.core.elements.JawaType
import org.json4s._
import org.json4s.JsonDSL._
import org.argus.jawa.core.util._

object IntentFilterDataBaseSerializer extends CustomSerializer[IntentFilterDataBase](format => (
    {
      case jv: JValue =>
        implicit val formats: Formats = format + JawaTypeSerializer + IntentFilterSerializer
        val intentFmap = (jv \ "intentFmap").extract[IMap[JawaType, ISet[IntentFilter]]]
        val ifdb = new IntentFilterDataBase
        ifdb.addIntentFmap(intentFmap)
        ifdb
    }, {
      case ifdb: IntentFilterDataBase =>
        implicit val formats: Formats = format + JawaTypeSerializer + IntentFilterSerializer
        "intentFmap" -> Extraction.decompose(ifdb.getIntentFmap)
    }
))

object IntentFilterSerializer extends CustomSerializer[IntentFilter](format => (
    {
      case jv: JValue =>
        implicit val formats: Formats = format + IfDataSerializer
        val holder = (jv \ "holder").extract[JawaType]
        val actions = (jv \ "actions").extract[ISet[String]]
        val categories = (jv \ "categories").extract[ISet[String]]
        val data = (jv \ "data").extract[Data]
        val ifilter = new IntentFilter(holder)
        ifilter.addActions(actions)
        ifilter.addCategories(categories)
        ifilter.addData(data)
        ifilter
    },
    {
      case ifilter: IntentFilter =>
        implicit val formats: Formats = format + IfDataSerializer
        ("holder" -> Extraction.decompose(ifilter.getHolder)) ~
        ("actions" -> ifilter.getActions) ~
        ("categories" -> ifilter.getCategorys) ~
        ("data" -> Extraction.decompose(ifilter.getData))
    }
))

object IfDataSerializer extends CustomSerializer[Data](format => (
    {
      case jv: JValue =>
        implicit val formats: Formats = format
        val schemes = (jv \ "schemes").extract[ISet[String]]
        val authorities = (jv \ "authorities").extract[ISet[Authority]]
        val paths = (jv \ "paths").extract[ISet[String]]
        val pathPrefixs = (jv \ "pathPrefixs").extract[ISet[String]]
        val pathPatterns = (jv \ "pathPatterns").extract[ISet[String]]
        val mimeTypes = (jv \ "mimeTypes").extract[ISet[String]]
        val d = new Data
        d.addSchemes(schemes)
        d.addAuthorities(authorities)
        d.addPaths(paths)
        d.addPathPrefixs(pathPrefixs)
        d.addPathPatterns(pathPatterns)
        d.addTypes(mimeTypes)
        d
    },
    {
      case d: Data =>
        implicit val formats: Formats = format
        ("schemes" -> d.getSchemes) ~
        ("authorities" -> Extraction.decompose(d.getAuthorities)) ~
        ("paths" -> d.getPaths) ~
        ("pathPrefixs" -> d.getPathPrefixs) ~
        ("pathPatterns" -> d.getPathPatterns) ~
        ("mimeTypes" -> d.getMimeTypes)
    }
))
