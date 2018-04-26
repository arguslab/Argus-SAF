/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.wu

import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.model.ModelCallHandler
import org.argus.jawa.alir.pta.{PTASlot, VarSlot}
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.summary.SummaryManager
import org.argus.jawa.summary.wu.{PTStore, PointsToWu}

class IntentWu(
    global: Global,
    method: JawaMethod,
    sm: SummaryManager,
    handler: ModelCallHandler,
    store: PTStore,
    key: String) extends PointsToWu[Global](global, method, sm, handler, store, key) {

  override def initFn(): Unit = {
    method.getBody.resolvedBody.locations foreach { loc =>
      val context = new Context(global.projectName)
      context.setContext(method.getSignature, loc.locationUri)
      loc.statement match {
        case cs: CallStatement if InterComponentCommunicationModel.isIccOperation(cs.signature) =>
          val trackedSlots: MSet[(PTASlot, Boolean)] = msetEmpty
          val intentSlot = VarSlot(cs.rhs.arg(1))
          trackedSlots += ((intentSlot, true))
          pointsToResolve(context) = trackedSlots.toSet
        case _ =>
      }
    }
  }

  override def toString: String = s"IntentWu($method)"
}