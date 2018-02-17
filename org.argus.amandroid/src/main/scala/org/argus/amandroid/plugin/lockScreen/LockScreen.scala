package org.argus.amandroid.plugin.lockScreen

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.core.{Global, JawaType}

class LockScreen(mainActivity:JawaType) {

  def checkLockScreen(global:Global,idfgOpt: Option[InterProceduralDataFlowGraph]): String ={

    val clazz=global.getClassOrResolve(mainActivity)
    if (!clazz.isSystemLibraryClass && clazz.isConcrete){
      clazz.getDeclaredMethods for each {method =>
        val code=method.getBody.toCode
        if (code.contains("Hello World")){
          return 'YES'
        }
        else return 'NO'

      }
    }

  }
}
