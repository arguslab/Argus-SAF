package org.argus.amandroid.plugin

import org.scalatest.FlatSpec

class LockScreenTest extends FlatSpec{

  "LockScreen" should "1 misuse" in {
    assert(1==isLockScreen())
  }

  private def isLockScreen()={
    val a=1
    a
  }



}

