/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.cg

import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.WorklistAlgorithm
import org.argus.jawa.core.util._

class CallGraph {
  /**
   * map from methods to it's callee methods
   * map from caller sig to callee sigs
   */
  private val callMap: MMap[Signature, MSet[Signature]] = mmapEmpty
  
  def addCall(from: Signature, to: Signature): MSet[Signature] = this.callMap.getOrElseUpdate(from, msetEmpty) += to
  def addCalls(from: Signature, to: ISet[Signature]): MSet[Signature] = this.callMap.getOrElseUpdate(from, msetEmpty) ++= to
  
  def getCallMap: IMap[Signature, ISet[Signature]] = this.callMap.map{case (k, vs) => k -> vs.toSet}.toMap

  def getReachableMethods(procs: ISet[Signature]): ISet[Signature] = {
    val result: MSet[Signature] = msetEmpty
    val worklistAlgorithm = new WorklistAlgorithm[Signature] {
      override def processElement(e: Signature): Unit = {
        if(result.contains(e)) return
        result += e
        worklist = callMap.getOrElse(e, msetEmpty) ++: worklist
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist = procs.toList)
    result.toSet
  }

  def topologicalSort(reverse: Boolean): IList[Signature] = {
    val list = TopologicalSortUtil.sort[Signature](getCallMap)
    if(reverse) list.reverse
    else list
  }
}