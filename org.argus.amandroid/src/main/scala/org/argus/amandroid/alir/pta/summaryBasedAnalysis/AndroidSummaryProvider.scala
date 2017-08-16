/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.summaryBasedAnalysis

import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.summaryBasedAnalysis.JawaSummaryProvider
import org.argus.jawa.core.Global

/**
  * Created by fgwei on 7/1/17.
  */
class AndroidSummaryProvider(global: Global)(implicit heap: SimHeap) extends JawaSummaryProvider(global) {
  sm.registerFileInternal("summaries/Bundle.safsu")
  sm.registerFileInternal("summaries/Activity.safsu")
  sm.registerFileInternal("summaries/ComponentName.safsu")
  sm.registerFileInternal("summaries/Uri.safsu")
  sm.registerFileInternal("summaries/Intent.safsu")
  sm.registerFileInternal("summaries/IntentFilter.safsu")
  sm.registerFileInternal("summaries/Context.safsu")
}
