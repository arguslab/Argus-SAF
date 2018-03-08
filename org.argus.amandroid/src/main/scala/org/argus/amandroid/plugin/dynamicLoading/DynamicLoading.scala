package org.argus.amandroid.plugin.dynamicLoading

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.ast.{AssignmentStatement, CallStatement}
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
    method.getBody.resolvedBody.locations.foreach { line =>
      line.statement match {
        case cs: CallStatement => {
          print(" ")
          if (cs.signature== "Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V")
          {
            val valuesForParam0=ExplicitValueFinder.findExplicitLiteralForArgs(method,line,cs.arg(0))
            val valuesForParam1=ExplicitValueFinder.findExplicitLiteralForArgs(method,line,cs.arg(1))
            val valuesForParam2=ExplicitValueFinder.findExplicitLiteralForArgs(method,line,cs.arg(2))
            val valuesForParam3=ExplicitValueFinder.findExplicitLiteralForArgs(method,line,cs.args(3))
            print(valuesForParam3)
          }
        }
        case _ =>
      }
    }
    hasDynamiLoading
  }
}

/* Load from network / phone or No
Check whether from Asset, Phone or Network
AMD
To-DO : Get the Contagio-Mini dump application

 */

