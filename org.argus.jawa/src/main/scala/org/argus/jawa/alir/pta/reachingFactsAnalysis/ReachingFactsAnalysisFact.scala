/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis

import org.argus.jawa.alir.pta.{Instance, PTASlot}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class RFAFact(slot: Int, ins: Int)(implicit factory: RFAFactFactory) {
  def this(s: PTASlot, v: Instance)(implicit factory: RFAFactFactory) = this(factory.getSlotNum(s), factory.getInstanceNum(v))
  def s: PTASlot = {
    factory.getSlot(slot)
  }
  def v: Instance = {
    factory.getInstance(ins)
  }

  override def toString: String = (s, v).toString()
}

class RFAFactFactory {
  private val slots: MList[PTASlot] = mlistEmpty
  private val instances: MList[Instance] = mlistEmpty
  def getSlotNum(slot: PTASlot): Int = {
    var n: Int = slots.indexOf(slot)
    if(n < 0) {
      n = slots.size
      slots += slot
    }
    n
  }
  /**
   * never call it using arbitrary num
   */
  def getSlot(num: Int): PTASlot = {
    slots(num)
  }
  def getInstanceNum(ins: Instance): Int = {
    var n: Int = instances.indexOf(ins)
    if(n < 0) {
      n = instances.size
      instances += ins
    }
    n
  }
  /**
   * never call it using arbitrary num
   */
  def getInstance(num: Int): Instance = {
    instances(num)
  }
}
