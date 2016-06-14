/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
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
