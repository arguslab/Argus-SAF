/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.model

import org.argus.amandroid.core.parser.UriData
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.util._

case class Intent(
    componentNames: ISet[String],
    actions: ISet[String],
    categories: ISet[String],
    data: ISet[UriData],
    types: ISet[String]) {
  val targets: MSet[JawaType] = msetEmpty
  var explicit: Boolean = false
  var precise: Boolean = false

  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Intent:\n")
    if(componentNames.nonEmpty) {
      sb.append("  Component Names:\n    ")
      sb.append(componentNames.mkString("\n    "))
      sb.append("\n")
    }
    if(actions.nonEmpty) {
      sb.append("  Actions:\n    ")
      sb.append(actions.mkString("\n    "))
      sb.append("\n")
    }
    if(categories.nonEmpty) {
      sb.append("  Categories:\n    ")
      sb.append(categories.mkString("\n    "))
      sb.append("\n")
    }
    if(data.nonEmpty) {
      sb.append("  Data:\n    ")
      sb.append(data.mkString("\n    "))
      sb.append("\n")
    }
    if(types.nonEmpty) {
      sb.append("  Types:\n    ")
      sb.append(types.mkString("\n    "))
      sb.append("\n")
    }
    sb.append("  Explicit: " + explicit)
    sb.append("\n")
    sb.append("  Precise: " + precise)
    sb.append("\n")
    if(targets.nonEmpty) {
      sb.append("  ICC Targets:\n    ")
      sb.append(targets.mkString("\n    "))
    }
    sb.toString().trim
  }
}