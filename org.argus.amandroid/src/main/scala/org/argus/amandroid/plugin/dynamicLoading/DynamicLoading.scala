package org.argus.amandroid.plugin.dynamicLoading

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.Global

class DynamicLoading {

  def checkDynamicLoading(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var hasDynamicLoading: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if ((f.code.contains("Landroid/view/WindowManager$LayoutParams;")) && (hasLockScreen == false)) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { x =>
              if (hasDynamicLoading == false) {
                hasDynamicLoading = checkPresence()
              }
            }
        }
      }
      hasDynamicLoading
    }

    def checkPresence(): Boolean = {
      true
    }

  }
}
