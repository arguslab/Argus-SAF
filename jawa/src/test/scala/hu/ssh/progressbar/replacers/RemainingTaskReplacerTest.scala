/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.replacers

import hu.ssh.progressbar.progress.Progress
import org.scalatest.{FlatSpec, Matchers}

class RemainingTaskReplacerTest extends FlatSpec with Matchers {
  "new Progress(5, 0, 0)" should "format to '5'" in {
    val replacer = new RemainingTaskReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 0, 0)) == "5")
  }
  "new Progress(5, 2, 200)" should "format to '3'" in {
    val replacer = new RemainingTaskReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 2, 200)) == "3")
  }
  "new Progress(5, 3, 3000)" should "format to '22'" in {
    val replacer = new RemainingTaskReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 3, 3000)) == "2")
  }
  "new Progress(5, 5, 200)" should "format to '0'" in {
    val replacer = new RemainingTaskReplacer
    assert(replacer.getReplacementForProgress(new Progress(5, 5, 200)) == "0")
  }
}
