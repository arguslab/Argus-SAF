/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary

import org.argus.jawa.core.Global

/**
  * Created by fgwei on 7/1/17.
  */
trait SummaryProvider {
  def getSummaryManager: SummaryManager
}

class JawaSummaryProvider(global: Global) extends SummaryProvider {
  val sm = new SummaryManager(global)
  sm.registerFile("summaries/Object.safsu", "Object.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Class.safsu", "Class.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/String.safsu", "String.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/StringBuilder.safsu", "StringBuilder.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/StringBuffer.safsu", "StringBuffer.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Map.safsu", "Map.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Set.safsu", "Set.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/List.safsu", "List.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Thread.safsu", "Thread.safsu", fileAndSubsigMatch = true)
  override def getSummaryManager: SummaryManager = sm
}
