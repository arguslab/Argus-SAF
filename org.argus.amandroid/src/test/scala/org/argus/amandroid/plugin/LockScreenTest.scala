package org.argus.amandroid.plugin

import org.argus.amandroid.plugin.lockScreen.LockScreen
import org.scalatest.FlatSpec

class LockScreenTest extends FlatSpec{

  "LockScreen" should "1 misuse" in {
    assert(isLockScreen())
  }

  private def isLockScreen():Boolean={
    val lockScreen=new LockScreen()
    var b:Boolean=lockScreen.checkLockScreen()
    b
  }
}

