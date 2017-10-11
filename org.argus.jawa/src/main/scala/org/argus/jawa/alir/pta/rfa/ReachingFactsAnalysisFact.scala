/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.rfa

import org.argus.jawa.alir.pta.{Instance, PTASlot}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class RFAFact(slot: PTASlot, ins: Int)(implicit factory: SimHeap) {
  def this(s: PTASlot, v: Instance)(implicit factory: SimHeap) = this(s, factory.getInstanceNum(v))
  def s: PTASlot = slot
  def v: Instance = {
    factory.getInstance(ins)
  }

  override def toString: String = (s, v).toString()
}

class SimHeap {
  private val instances: MList[Instance] = mlistEmpty

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
