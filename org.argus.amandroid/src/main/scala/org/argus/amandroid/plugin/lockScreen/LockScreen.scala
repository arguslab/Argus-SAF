package org.argus.amandroid.plugin.lockScreen

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.{Global, JawaType}

class LockScreen(mainActivity:JawaType) {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var isFlag:Boolean=false
    isFlag
  }

}

/* Steps
1. Get the control flow graph from a given APK
2. Check each of the nodes in the CFG
3. If any of the nodes contain the malicious signature, set the Flag as true
4. Return the Flag
5. Test it with the test script 
 */