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
      if (f.code.contains("Landroid/view/WindowManager;.addView:(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V")) {
        global.getClazz(typ) match {
          case Some(c)=>
            c.getDeclaredMethods.foreach {x =>
              {
                print(x)
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
          print(cs)
      }
      }
          /*if (cs.signature.getSubSignature=="Landroid/view/WindowManager;.addView:(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V"){
            print("Yes")
          }
          else {
            print("No")
          }
          */

    }
    // m is the resolved method
    // check contain signature
    // m.statements or m.node or something like that
    // use Explicitvaluefinder

    // Here check each of the methods in the Class.
    true
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