/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.gpu

import java.io.Writer

import org.argus.jawa.alir.JawaAlirInfoProvider
import org.argus.jawa.alir.cfg.{CFGLocationNode, CFGNode}
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.ast.MethodDeclaration
import org.argus.jawa.core.{Global, Signature}
import org.jgrapht.ext.ComponentNameProvider

class GPUSummaryBasedAnalysis {

  private def vLabelProvider(body: MethodDeclaration): ComponentNameProvider[CFGNode] = {
    case ln: CFGLocationNode =>
      val locUri = ln.toString
      val l = body.resolvedBody.location(locUri)
      l.statement.toStructure
    case _ =>
      null
  }

  def prepareData(global: Global, ep: Signature, w: Writer): Unit = {
    val cg = SignatureBasedCallGraph(global, Set(ep), None)
    val sorted = cg.topologicalSort(true)
    sorted.foreach { sig =>
      val method = global.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
      if(method.getDeclaringClass.isApplicationClass) {
        val body = method.getBody
        val cfg = JawaAlirInfoProvider.getCfg(method)
        cfg.toGraphML(w, vlp = vLabelProvider(body))
      }
    }
  }
}
