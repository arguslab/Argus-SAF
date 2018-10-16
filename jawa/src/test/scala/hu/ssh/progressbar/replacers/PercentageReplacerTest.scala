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
class PercentageReplacerTest extends FlatSpec with Matchers {
  "new Progress(5, 0, 0)" should "format to '  0.00'" in {
    val replacer = new PercentageReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 0, 0)) == "  0.00")
  }
  "new Progress(5, 2, 200)" should "format to ' 40.00'" in {
    val replacer = new PercentageReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 2, 200)) == " 40.00")
  }
  "new Progress(5, 3, 3000)" should "format to ' 60.00'" in {
    val replacer = new PercentageReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 3, 0)) == " 60.00")
  }
  "new Progress(5, 5, 200)" should "format to '100.00'" in {
    val replacer = new PercentageReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 5, 200)) == "100.00")
  }
}
