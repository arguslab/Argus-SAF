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

import org.argus.jawa.core.Global
import org.argus.jawa.summary.JawaSummaryProvider

/**
  * Created by fgwei on 7/1/17.
  */
class AndroidSummaryProvider(global: Global) extends JawaSummaryProvider(global) {
  sm.registerFile("summaries/Bundle.safsu", "Bundle.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Activity.safsu", "Activity.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/ComponentName.safsu", "ComponentName.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Uri.safsu", "Uri.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Intent.safsu", "Intent.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/IntentFilter.safsu", "IntentFilter.safsu", fileAndSubsigMatch = true)
  sm.registerFile("summaries/Context.safsu", "Context.safsu", fileAndSubsigMatch = true)
}
