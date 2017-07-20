/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis

import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.core.Global

/**
  * Created by fgwei on 7/1/17.
  */
trait SummaryProvider {
  def getSummaryManager: SummaryManager
}

class JawaSummaryProvider(global: Global)(implicit heap: SimHeap) extends SummaryProvider {
  val sm = new SummaryManager(global)
  sm.registerFileInternal("summaries/Object.safsu")
  sm.registerFileInternal("summaries/Class.safsu")
  sm.registerFileInternal("summaries/String.safsu")
  sm.registerFileInternal("summaries/StringBuilder.safsu")
  sm.registerFileInternal("summaries/StringBuffer.safsu")
  sm.registerFileInternal("summaries/Map.safsu")
  sm.registerFileInternal("summaries/Set.safsu")
  sm.registerFileInternal("summaries/List.safsu")
  sm.registerFileInternal("summaries/Thread.safsu")
  override def getSummaryManager: SummaryManager = sm
}
