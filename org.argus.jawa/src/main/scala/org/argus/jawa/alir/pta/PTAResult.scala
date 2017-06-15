/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta

import org.argus.jawa.alir.Context
import org.argus.jawa.core.util._

object PTAResult {
  type PTSMap = IMap[PTASlot, ISet[Instance]]
}

class PTAResult {
  import PTAResult._
  
  private val beforeMap: MMap[Context, MMap[PTASlot, MSet[Instance]]] = mmapEmpty
  private val afterMap: MMap[Context, MMap[PTASlot, MSet[Instance]]] = mmapEmpty
  private def ptMap(after: Boolean) = if(after) afterMap else beforeMap

  def pointsToMap(after: Boolean): IMap[Context, PTSMap] = {
    ptMap(after).map{
      case (c, m) =>
        (c, m.map{
          case (str, s) =>
            (str, s.toSet)
        }.toMap)
    }.toMap
  }
  
  def addPointsToMap(after: Boolean, ptMap: IMap[Context, PTSMap]): Unit = {
    ptMap.foreach {
      case (c, m) =>
        m.foreach {
          case (str, s) =>
            addInstances(after, c, str, s)
        }
    }
  }
  
  def merge(result: PTAResult): PTAResult = {
    addPointsToMap(after = false, result.pointsToMap(false))
    addPointsToMap(after = true, result.pointsToMap(true))
    this
  }
  
  def setInstance(after: Boolean, context: Context, s: PTASlot, i: Instance): Unit = {
    ptMap(after)(context)(s) = msetEmpty + i
  }
  def setInstances(after: Boolean, context: Context, s: PTASlot, is: ISet[Instance]): Unit = {
    ptMap(after)(context)(s) = msetEmpty ++ is
  }
  def addInstance(after: Boolean, context: Context, s: PTASlot, i: Instance): Unit = ptMap(after).getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) += i
  def addInstances(after: Boolean, context: Context, s: PTASlot, is: ISet[Instance]): Unit = ptMap(after).getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) ++= is
  def removeInstance(after: Boolean, context: Context, s: PTASlot, i: Instance): Unit =
    ptMap(after).getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) -= i
  def removeInstances(after: Boolean, context: Context, s: PTASlot, is: ISet[Instance]): Unit =
    ptMap(after).getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) --= is
  def pointsToSet(after: Boolean, context: Context, s: PTASlot): ISet[Instance] =
    ptMap(after).getOrElse(context, mmapEmpty).getOrElse(s, msetEmpty).toSet
  def getPTSMap(after: Boolean, context: Context): PTSMap = {
    ptMap(after).getOrElseUpdate(context, mmapEmpty).map{
      case (str, s) =>
        (str, s.toSet)
    }.toMap
  }

  def getRelatedInstances(after: Boolean, context: Context, s: PTASlot): ISet[Instance] = {
    val bValue = pointsToSet(after, context, s)
    val rhValue = getRelatedHeapInstances(after, context, bValue)
    bValue ++ rhValue
  }
  def getRelatedHeapInstances(after: Boolean, context: Context, insts: ISet[Instance]): ISet[Instance] = {
    val processed: MSet[Instance] = msetEmpty
    var result: ISet[Instance] = isetEmpty
    val worklistAlgorithm = new WorklistAlgorithm[Instance] {
      override def processElement(ins: Instance): Unit = {
        processed += ins
        val hMap = getPTSMap(after, context).filter{case (s, _) => s.isInstanceOf[HeapSlot] && s.asInstanceOf[HeapSlot].matchWithInstance(ins)}
        val hInss = hMap.flatMap(_._2).toSet
        result ++= hInss
        worklist ++= hInss.diff(processed)
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist ++= insts)
    result
  }
}
