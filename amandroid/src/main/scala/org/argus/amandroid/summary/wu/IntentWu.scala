/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.wu

import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.model.ModelCallHandler
import org.argus.jawa.flow.pta.{PTASlot, VarSlot}
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.flow.summary.SummaryManager
import org.argus.jawa.flow.summary.wu.{PTStore, PointsToWu}

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