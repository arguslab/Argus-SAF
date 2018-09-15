/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.helpers

import org.scalatest.{FlatSpec, Matchers}

/**
  * Created by fgwei on 5/2/17.
  */
class HumanTimeFormatterTest extends FlatSpec with Matchers {
  "0L" should "format to 0ms" in {
    assert(HumanTimeFormatter.formatTime(0L) == "0ms")
  }
  "150L" should "format to 150ms" in {
    assert(HumanTimeFormatter.formatTime(150L) == "150ms")
  }
  "6005L" should "format to 6s5ms" in {
    assert(HumanTimeFormatter.formatTime(6005L) == "6s5ms")
  }
  "600001L" should "format to 10m1ms" in {
    assert(HumanTimeFormatter.formatTime(600001L) == "10m1ms")
  }
  "5061616105L" should "format to 58d14h16s105ms" in {
    assert(HumanTimeFormatter.formatTime(5061616105L) == "58d14h16s105ms")
  }
}
