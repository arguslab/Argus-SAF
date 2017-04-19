/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

/**
  * Simple implementation of a worklist algorithm. A processing
  * function is applied repeatedly to the first element in the
  * worklist, as long as the stack is not empty.
  *
  * The client class should mix-in this class and initialize the
  * worklist field and define the <code>processElement</code> method.
  * Then call the <code>run</code> method providing a function that
  * initializes the worklist.
  *
  * @author  Martin Odersky
  */
trait WorklistAlgorithm[Elem] {

  var worklist: IList[Elem] = ilistEmpty

  /**
    * Run the iterative algorithm until the worklist
    * remains empty. The initializer is run once before
    * the loop starts and should initialize the worklist.
    *
    * @param initWorklist ...
    */
  def run(initWorklist: => Unit): Unit = {
    initWorklist

    while (worklist.nonEmpty)
      processElement(dequeue)
  }

  /**
    * Process the current element from the worklist.
    */
  def processElement(e: Elem): Unit

  /**
    * Remove and return the first element to be processed from the worklist.
    */
  def dequeue: Elem = {
    val e = worklist.head
    worklist = worklist.tail
    e
  }
}