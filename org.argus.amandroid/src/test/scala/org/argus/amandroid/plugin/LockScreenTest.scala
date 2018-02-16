package org.argus.amandroid.plugin

import org.argus.amandroid.plugin.lockScreen.LockScreen
import org.scalatest.FlatSpec

class LockScreenTest extends FlatSpec{

  "LockScreen" should "1 misuse" in {
    assert(1==isLockScreen())
  }

  private def isLockScreen():Int={
    val lockScreen=new LockScreen()
    var b:Int=lockScreen.testFunction()
    b
  }
}

