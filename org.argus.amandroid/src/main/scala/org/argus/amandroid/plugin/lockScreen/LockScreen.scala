package org.argus.amandroid.plugin.lockScreen

import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.ast.{AssignmentStatement, CallStatement}
import org.argus.jawa.core.{Global, JawaMethod, JawaType}

class LockScreen() {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var isFlag: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if ((f.code.contains("Landroid/view/WindowManager$LayoutParams;"))&&(isFlag==false)) {
        global.getClazz(typ) match {
          case Some(c)=>
            c.getDeclaredMethods.foreach {x =>
              {
                isFlag=checkPresence(x)
              }
            }
            }
        }
      }
    isFlag
    }

  def checkPresence(method: JawaMethod):Boolean=
  {
    var isFlag: Boolean = false
    method.getBody.resolvedBody.locations.foreach{line =>
      line.statement match {
        case cs:CallStatement=>{
          if (cs.signature== "Landroid/view/WindowManager$LayoutParams;.<init>:(IIIII)V") {
            val valuesForParam0 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(0))
            val valuesForParam1 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(1))
            val valuesForParam2 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(2))
            val valuesForParam3 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(3))
            val valuesForParam4 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(4))

            if (valuesForParam2.filter(_.isInt).map(_.getInt).contains(256)) {
              isFlag = true
            }
            else if (valuesForParam3.filter(_.isInt).map(_.getInt).contains(1024)) {
              isFlag = true
            }
          }
          }
        case cs:AssignmentStatement=>
          {
            if (cs.toCode.contains("android")){
              val str=cs.getRhs.toString
              isFlag=true
            }
          }
        case _ => 
      }
    }
    isFlag
  }
}
