/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.report

import org.argus.amandroid.core.parser.Data
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.util._

class ReportGen(apk_name: String) {
  
  case class CompInfo(compTyp: JawaType, typ: String, exported: Boolean, permission: ISet[String] = isetEmpty) {
    val intentFilters: MSet[IntentFilter] = msetEmpty
    def addIntentFilter(actions: ISet[String], categories: ISet[String], data: Data) =
      intentFilters += IntentFilter(actions, categories, data)
  }
  
  case class IntentFilter(actions: ISet[String], categories: ISet[String], data: Data = null)
  
  val permissions:  MSet[String] = msetEmpty
  val libLoaded:  MSet[String] = msetEmpty
  val comps: MSet[CompInfo] = msetEmpty
  val urls: MSet[String] = msetEmpty
  
  def genComp(compTyp: JawaType, typ: String, exported: Boolean, permission: ISet[String] = isetEmpty): CompInfo =
    CompInfo(compTyp, typ, exported, permission)

  override def toString: String = {
    def appendComp(comp: CompInfo, b: StringBuilder) = {
      b.append("\n" + comp.compTyp + "\n")
      b.append("exported: " + comp.exported + "\n")
      if(comp.permission.nonEmpty)
        b.append("permission: " + comp.permission + "\n")
      if(comp.intentFilters.nonEmpty){
        b.append("IntentFilters: \n")
        var n = 0
        comp.intentFilters.foreach{
          intf =>
            n += 1
            b.append("Filter" + n + ":\n")
            if(intf.actions.nonEmpty){
              b.append("  actions:")
              intf.actions.foreach{
                a =>
                  b.append(" " + a)
              }
              b.append("\n")
            }
            if(intf.categories.nonEmpty){
              b.append("  categories:")
              intf.categories.foreach{
                a =>
                  b.append(" " + a)
              }
              b.append("\n")
            }
            if(intf.data != null && !intf.data.isEmpty){
              b.append("  data: " + intf.data.toString() + "\n")
            }
        }
      }
    }
    val b = new StringBuilder
    b.append("App name: " + apk_name + "\n\n")
    if(permissions.nonEmpty){
      b.append("Used permissions: \n")
      permissions.foreach{
        perm =>
          b.append(perm + "\n")
      }
      b.append("\n")
    }
    val acs = comps.filter { c => c.typ == "activity" }
    if(acs.nonEmpty){
      b.append("Activities displayed by the app: \n")
      acs.foreach{
        ac =>
          appendComp(ac, b)
      }
      b.append("\n")
    }
    val res = comps.filter { c => c.typ == "receiver" }
    if(res.nonEmpty){
      b.append("Events monitored by the app: \n")
      res.foreach{
        re =>
          appendComp(re, b)
      }
      b.append("\n")
    }
    val ses = comps.filter { c => c.typ == "service" }
    if(ses.nonEmpty){
      b.append("Services run by the app: \n")
      ses.foreach{
        se =>
          appendComp(se, b)
      }
      b.append("\n")
    }
    if(libLoaded.nonEmpty){
      b.append("Libraries loaded by the app: \n")
      libLoaded.foreach{
        lib =>
          b.append(lib + "\n")
      }
      b.append("\n")
    }
    if(urls.nonEmpty){
      b.append("Urls in the apk: \n")
      urls.foreach{
        url =>
          b.append(url + "\n")
      }
    }
    b.append("\n\n")
    b.toString().trim()
  }
}
