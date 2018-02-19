package org.argus.amandroid.plugin.lockScreen

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.{Global, JawaType}

class LockScreen() {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var isFlag: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if (f.code.contains("lockscreen")) {
        isFlag = true
      }
    }
    isFlag
  }
}

/* Steps
Iteration 1:

1. Get the control flow graph from a given APK
2. Check each of the nodes in the CFG
3. If any of the nodes contain the malicious signature, set the Flag as true
4. Return the Flag
5. Test it with the test script

Iteration 2:
What if the signature is in a service but that service/ class is never started ?
 */