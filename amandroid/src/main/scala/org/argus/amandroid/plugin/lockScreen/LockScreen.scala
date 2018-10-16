/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.lockScreen
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.argus.jawa.core.ast._
import org.argus.jawa.core.{Global, JawaMethod}

class LockScreen() {

  def checkLockScreen(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): Boolean = {
    var hasLockScreen: Boolean = false
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if (f.code.contains("Landroid/view/WindowManager$LayoutParams;") && !hasLockScreen) {
        global.getClazz(typ) match {
          case Some(c)=>
            c.getDeclaredMethods.foreach {x =>
              if (!hasLockScreen) {
                hasLockScreen=checkPresence(x)
              }
            }
          case None =>
        }
      }
    }
    hasLockScreen
  }

  def checkPresence(method: JawaMethod):Boolean = {
    var hasLockScreen: Boolean = false
    method.getBody.resolvedBody.locations.foreach { line =>
      line.statement match {
        case cs: CallStatement =>
          if (cs.signature.signature == "Landroid/view/WindowManager$LayoutParams;.<init>:(IIIII)V") {
            val valuesForParam3 = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, cs.arg(3))
            val set=valuesForParam3.filter(_.isInt).map(_.getInt)

            // Check FLAG_FULLSCREEN.
            if (set.contains(1024)|set.contains(2010)) {
              hasLockScreen = true
            }
          }
        case cs: AssignmentStatement =>
          cs.lhs match {
            case ae: AccessExpression =>
              if (ae.toString.contains("android.view.WindowManager$LayoutParams.type")) {
                print(ae)
                cs.getRhs match {
                  case ne: VariableNameExpression =>
                    val varName = ne.name
                    val rhsValue = ExplicitValueFinder.findExplicitLiteralForArgs(method, line, varName)
                    val set = rhsValue.filter(_.isInt).map(_.getInt)
                    if (set.contains(2010) || set.contains(1024)) {
                      hasLockScreen = true
                    }
                  case _=>
                }
              }
            case _ =>
          }
        case _ =>
      }
    }
    hasLockScreen
  }
}
