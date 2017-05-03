/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.console.replacers

import hu.ssh.progressbar.Progress
import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 5/3/17.
  */
class BarReplacerTest extends FlatSpec with Matchers {

  "new Progress(5, 0, 0)" should "format to '-----'" in {
    val replacer = new BarReplacer(5)
    assert(replacer.getReplacementForProgress(new Progress(5, 0, 0)) == "-----")
  }

  "new Progress(5, 2, 0)" should "format to '==---'" in {
    val replacer = new BarReplacer(5)
    assert(replacer.getReplacementForProgress(new Progress(5, 2, 0)) == "==---")
  }

  "new Progress(5, 3, 0)" should "format to '===--'" in {
    val replacer = new BarReplacer(5)
    assert(replacer.getReplacementForProgress(new Progress(5, 3, 0)) == "===--")
  }

  "new Progress(5, 5, 0)" should "format to '====='" in {
    val replacer = new BarReplacer(5)
    assert(replacer.getReplacementForProgress(new Progress(5, 5, 0)) == "=====")
  }
}
