/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.util._

import scala.collection.immutable.BitSet

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ClassLoadManager {
  /**
   * set of classes can be loaded by the program
   */
  private var classes: IList[JawaClass] = ilistEmpty

  def reset(): Unit = classes = ilistEmpty

  protected def addClass(clazz: JawaClass): Unit = {
    this.synchronized(
      this.classes :+= clazz
    )
  }

  def getClassPosition(clazz: JawaClass): Int = {
    if(!this.classes.contains(clazz)) addClass(clazz)
    this.classes.indexOf(clazz)
  }

  def loadClass(clazz: JawaClass): BitSet = {
    val position = getClassPosition(clazz)
    if(position < 0){
      throw new RuntimeException("Negative position:" + position)
    }
    BitSet(position)
  }

  def loadClass(clazz: JawaClass, bitset: BitSet): BitSet = {
    require(!isLoaded(clazz, bitset))
    val position = getClassPosition(clazz)
    if(position < 0){
      throw new RuntimeException("Negative position:" + position)
    }
    bitset + position
  }
  
  def isLoaded(clazz: JawaClass, bitset: BitSet): Boolean = {
    val position = getClassPosition(clazz)
    bitset(position)
  }
}
