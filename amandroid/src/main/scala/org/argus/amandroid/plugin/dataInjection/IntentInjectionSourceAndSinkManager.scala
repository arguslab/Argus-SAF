/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.dataInjection

import org.argus.amandroid.alir.taintAnalysis.{AndroidSourceAndSinkManager, IntentSinkKind}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.elements.Signature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentInjectionSourceAndSinkManager(sasFilePath: String) extends AndroidSourceAndSinkManager(sasFilePath){

  override def isEntryPointSource(apk: ApkGlobal, signature: Signature): Boolean = {
    apk.model.getEnvMap.exists{ case (_, (sig, _)) =>
      signature == sig && sig.methodName == "envMain"
    }
  }

  override def intentSink: IntentSinkKind.Value = IntentSinkKind.ALL
}
