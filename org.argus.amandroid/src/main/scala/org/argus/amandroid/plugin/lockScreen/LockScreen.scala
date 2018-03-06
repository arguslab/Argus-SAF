package org.argus.amandroid.plugin.lockScreen

import com.github.javaparser.ast.expr.NameExpr
import org.argus.jawa.ast.Expression
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.ast.{AccessExpression, AssignmentStatement, CallStatement, VariableNameExpression}
import org.argus.jawa.core.{Global, JawaMethod, JawaType}

class LockScreen() {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var hasLockScreen: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if ((f.code.contains("Landroid/view/WindowManager$LayoutParams;"))&&(hasLockScreen==false)) {
        global.getClazz(typ) match {
          case Some(c)=>
            c.getDeclaredMethods.foreach {x =>
              if (hasLockScreen==false)
              {
                hasLockScreen=checkPresence(x)
              }
            }
            }
        }
      }
    hasLockScreen
    }

  def checkPresence(method: JawaMethod):Boolean=
  {
    var hasLockScreen: Boolean = false
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
              hasLockScreen = true
            }
            else if (valuesForParam3.filter(_.isInt).map(_.getInt).contains(1024)) {
              hasLockScreen = true
            }
          }
          }
        case cs:AssignmentStatement=>
          {
            print(cs.getLhs.toString)
            print("Hello")
              if (cs.getLhs.toString.contains("android.view.WindowManager$LayoutParams.type"))
                {
                cs.getRhs match {
                  case ne: Expression => {
                    val varName = ne.toString
                    val rhsValue=ExplicitValueFinder.findExplicitLiteralForArgs(method, line, varName)
                    print(rhsValue)
                    hasLockScreen=true
                  }
                }
                }
            }
              // Here, I want to check the value on the right hand side and make proper decision.
              // But I am not able to figure out how we can do that
        case _ => 
      }
    }
    hasLockScreen
}
}
