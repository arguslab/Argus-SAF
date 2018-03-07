package org.argus.amandroid.plugin.dynamicLoading

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}

class DynamicLoading {
  def checkDynamicLoading(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var hasDynamicLoading: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if ((f.code.contains("Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V") && hasDynamicLoading == false)) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              if (hasDynamicLoading == false) {
                hasDynamicLoading = checkPresence(m)
              }
            }
        }
      }

    }
    hasDynamicLoading
  }

  def checkPresence(method: JawaMethod): Boolean = {
    var hasDynamiLoading: Boolean = false
    print(method.toString)
    method.getBody.resolvedBody.locations.foreach { line =>
      line.statement match {
        case cs: CallStatement => {
          print(cs.signature)
          print(" ")
          if (cs.signature == "Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V")
          {
            hasDynamiLoading = true
          }
        }
      }
    }
    hasDynamiLoading
  }
}

