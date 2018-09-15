/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.analysis

import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.cfg.ICFGCallNode
import org.argus.jawa.alir.pta.PTAResult

/**
  * Created by fgwei on 4/27/17.
  */
class JNISourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath) {

  override def isIntentSink(apk: ApkGlobal, invNode: ICFGCallNode, pos: Option[Int], s: PTAResult): Boolean = false
}
