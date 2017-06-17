/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.alir.pta.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.core.{Constants, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class MapModel extends ModelCall {
  def isModelCall(p: JawaMethod): Boolean = {
    if(p.getDeclaringClass.isApplicationClass) false
    else {
      val map = p.getDeclaringClass.global.getClassOrResolve(new JawaType(Constants.MAP))
      val res = p.getDeclaringClass.global.getClassHierarchy.getAllImplementersOf(map).contains(p.getDeclaringClass)
      res
    }
  }

  private val safsuFile: String = "map.safsu"

  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    (isetEmpty, isetEmpty, false)
  }

  override def doModelCall(
      sm: SummaryManager,
      s: ISet[RFAFact],
      p: JawaMethod,
      retOpt: Option[String],
      recvOpt: Option[String],
      args: IList[String],
      currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], Boolean) = {
    val summaries = sm.getSummaries(safsuFile)
    summaries.get(p.getSignature) match {
      case Some(summary) =>
        (sm.process(summary, retOpt, recvOpt, args, s, currentContext), true)
      case None =>
        (s, false)
    }
  }
}
