/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.analysis

import org.argus.amandroid.alir.taintAnalysis.{DataLeakageAndroidSourceAndSinkManager, IntentSinkKind}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cfg.ICFGCallNode
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.flow.taintAnalysis.{SSPosition, SourceAndSinkCategory}

/**
  * Created by fgwei on 4/27/17.
  */
class JNISourceAndSinkManager(sasFilePath: String) extends DataLeakageAndroidSourceAndSinkManager(sasFilePath) {

  override def isSinkMethod(global: ApkGlobal, sig: Signature): Option[(String, ISet[SSPosition])] = {
    val poss = this.customSinks.getOrElse("ICC", mmapEmpty).filter(sink => matches(global, sig, sink._1)).map(_._2._1).fold(isetEmpty)(iunion)
    if(poss.nonEmpty) {
      Some((SourceAndSinkCategory.ICC_SINK, poss))
    } else {
      super.isSinkMethod(global, sig)
    }
  }

  override def intentSink: IntentSinkKind.Value = IntentSinkKind.ALL

  override def isIntentSink(apk: ApkGlobal, invNode: ICFGCallNode, pos: Option[Int], s: PTAResult): Boolean = {
    getCustomSinks("ICC").contains(invNode.getCalleeSig) || super.isIntentSink(apk, invNode, pos, s)
  }

  override def isEntryPointSource(apk: ApkGlobal, signature: Signature): Boolean = {
    apk.model.getComponentInfos foreach { info =>
      if(info.compType == signature.classTyp) {
        return apk.getEntryPoints(info).contains(signature)
      }
    }
    false
  }
}