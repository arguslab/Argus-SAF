/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary

import hu.ssh.progressbar.ProgressBar
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.core.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.summary.wu.WorkUnit

/**
  * Created by fgwei on 6/27/17.
  */
class BottomUpSummaryGenerator(
    sm: SummaryManager,
    handler: ModelCallHandler,
    suGen: (Signature, IList[SummaryRule]) => Summary,
    progressBar: ProgressBar)(implicit heap: SimHeap) {

  def build(orderedWUs: IList[WorkUnit]): Unit = {
    ProgressBarUtil.withProgressBar("Summary based data flow analysis...", progressBar)(orderedWUs, processWU)
  }

  private def processWU: WorkUnit => Unit = { wu =>
    if(!handler.isModelCall(wu.method)) {
      val summary = wu.generateSummary(suGen)
      sm.register(wu.method.getSignature, summary)
    }
  }
}
