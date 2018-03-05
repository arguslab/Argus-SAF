package org.argus.amandroid.plugin.dynamicLoading

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.Global

class DynamicLoading {

  def checkDynamicLoading(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]):Boolean ={
    checkPresence()
  }

  def checkPresence():Boolean={
    true
  }

}
