package org.argus.amandroid.plugin.lockScreen

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.alir.util.ExplicitValueFinder.findExplicitLiteralForArgs
import org.argus.jawa.ast.CallStatement
import org.argus.jawa.core.{Global, JawaMethod, JawaType}

class LockScreen() {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var isFlag: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if (f.code.contains("Landroid/view/WindowManager$LayoutParams;.<init>:(IIIII)V")) {
        global.getClazz(typ) match {
          case Some(c)=>
            c.getDeclaredMethods.foreach {x =>
              {
                checkPresence(x)
              }
            }
            }
        }
      }
    isFlag
    }

  def checkPresence(method: JawaMethod):Boolean=
  {
    method.getBody.resolvedBody.locations.foreach{l =>
      l.statement match {
        case cs:CallStatement=>{
          if (cs.signature.getSubSignature == "Landroid/view/WindowManager$LayoutParams;.<init>:(IIIII)V"){
            val valuesForParam1 = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(1))
            print(valuesForParam1)
          }

          }
        case _ => 
      }
    }
    true
  }
}

/*
Iteration 2:
What if the signature is in a service but that service/ class is never started ?
 */