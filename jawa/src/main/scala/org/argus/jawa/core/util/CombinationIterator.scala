/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object CombinationIterator {
	private def combination[T](xx: List[List[T]], i: Int): List[T] = xx match {
    case Nil => Nil
    case x :: xs => x(i % x.length) :: combination[T](xs, i / x.length)
  }                                              
  
  def combinationIterator[T](ll: List[List[T]]): Iterator[List[T]] = {
    Iterator.from(0).takeWhile(n => n < ll.map(_.length).product).map(combination[T](ll,_))
  }
}
