/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.taintAnalysis

import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.{Instance, PTASlot}
import org.argus.jawa.flow.rda.Slot

object TaintSlotPosition extends Enumeration {
  val LHS, RHS, ARG = Value
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait TaintSlot extends Slot {
  def context: Context
  def pos: TaintSlotPosition.Value
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final case class InstanceTaintSlot(s: PTASlot, pos: TaintSlotPosition.Value, context: Context, ins: Instance) extends TaintSlot

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final case class PrimitiveTaintSlot(s: PTASlot, pos: TaintSlotPosition.Value, context: Context) extends TaintSlot

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
final case class TaintFact(s: TaintSlot, tag: String){
  def getContext: Context = s.context
  override def toString: String = {
    "TaintFact" + "(" + s + ":" + tag + ")"
  }
}
