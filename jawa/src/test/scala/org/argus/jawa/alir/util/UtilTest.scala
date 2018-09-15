/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.util

import org.argus.jawa.core.util._
import org.argus.jawa.summary.util.TopologicalSortUtil
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 5/18/17.
  */
class UtilTest extends FlatSpec with Matchers {

  "TopologicalSort" should "work for Acyclic Graph" in {
    var map: IMap[Int, ISet[Int]] = imapEmpty
    map += 0 -> Set(1, 2)
    map += 1 -> Set(2, 3)
    map += 2 -> Set(3)
    assert(TopologicalSortUtil.sort(map) == List(0, 1, 2, 3))
  }

}
