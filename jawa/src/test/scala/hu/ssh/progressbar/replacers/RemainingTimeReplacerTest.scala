/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.replacers

import hu.ssh.progressbar.progress.Progress
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 5/3/17.
  */
class RemainingTimeReplacerTest extends FlatSpec with Matchers {
  "new Progress(5, 0, 0)" should "format to '?'" in {
    val replacer = new RemainingTimeReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 0, 0)) == "?")
  }
  "new Progress(5, 2, 200)" should "format to '300ms'" in {
    val replacer = new RemainingTimeReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 2, 200)) == "300ms")
  }
  "new Progress(5, 3, 3000)" should "format to '2s'" in {
    val replacer = new RemainingTimeReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 3, 3000)) == "2s")
  }
  "new Progress(5, 5, 200)" should "format to '0ms'" in {
    val replacer = new RemainingTimeReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 5, 200)) == "0ms")
  }
}
