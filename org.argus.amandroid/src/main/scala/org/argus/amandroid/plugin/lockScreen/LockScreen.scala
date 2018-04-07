/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.lockScreen
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.ast._
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
    method.getBody.resolvedBody.locations.foreach { line =>
      line.statement match {
        case cs: CallStatement => {
          if (cs.signature == "Landroid/view/WindowManager$LayoutParams;.<init>:(IIIII)V") {
            val valuesForParam0 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(0))
            val valuesForParam1 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(1))
            val valuesForParam2 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(2))
            val valuesForParam3 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(3))
            val valuesForParam4 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(4))
            val set=valuesForParam3.filter(_.isInt).map(_.getInt)

            // Check FLAG_FULLSCREEN.
            if (set.contains(1024)|set.contains(2010)) {
              hasLockScreen = true
            }
          }
        }
        case cs: AssignmentStatement => {
          cs.getLhs match {
            case ae:Some[AccessExpression] => {
              if (ae.toString.contains("android.view.WindowManager$LayoutParams.type")) {
                print(ae)
                cs.getRhs match {
                  case ne: VariableNameExpression => {
                    val varName = ne.name
                    val rhsValue = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, varName)
                    val set = rhsValue.filter(_.isInt).map(_.getInt)
                    if (set.contains(2010) || set.contains(1024)) {
                      hasLockScreen = true
                    }
                  }
                  case _=>
                }

              }
            }
            case _ =>
          }

        }
        case _ =>
      }
    }
    hasLockScreen
  }
}
