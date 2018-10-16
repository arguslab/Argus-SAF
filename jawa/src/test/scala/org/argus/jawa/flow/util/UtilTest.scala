/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.util

import org.argus.jawa.core.util._
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
