/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta

import org.argus.jawa.flow.rda.Slot
import org.argus.jawa.core.elements.Signature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class PTASlot(id: Any) extends Slot {
  def getId: Any = this.id
}

abstract class NameSlot(name: String) extends PTASlot(name) {
  override def toString: String = name
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
final case class VarSlot(varName: String) extends NameSlot(varName) {
  override def toString: String = varName
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
final case class StaticFieldSlot(fqn: String) extends NameSlot(fqn)

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
abstract class HeapSlot(ins: Instance) extends PTASlot(ins){
  def instance: Instance = ins
  def matchWithInstance(ins: Instance): Boolean = this.ins == ins
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class FieldSlot(ins: Instance, fieldName: String) extends HeapSlot(ins){
  override def toString: String = ins.toString + "." + fieldName
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class ArraySlot(ins: Instance) extends HeapSlot(ins){
  override def toString: String = ins.toString + "[]"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class InstanceSlot(ins: Instance) extends PTASlot(ins){
  override def toString: String = ins.toString
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class InvokeSlot(sig: Signature, invTyp: String) extends PTASlot(sig){
  override def toString: String = "Invoke: " + invTyp + " " + sig
}