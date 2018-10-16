/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.jawa.core.util._
import java.net.URI
import java.net.URLEncoder

import org.argus.amandroid.core.model.Intent
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser.UriData
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta.{FieldSlot, Instance, PTAConcreteStringInstance, PTAResult}
import org.argus.jawa.core.elements.JawaType

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object IntentHelper {
  final val TITLE = "IntentHelper"
  val DEBUG = false
  
  object IntentType extends Enumeration {
    val EXPLICIT, IMPLICIT = Value
  }
  
  def getIntentContents(s: PTAResult, intentValues: ISet[Instance], currentContext: Context): ISet[Intent] = {
    var result = isetEmpty[Intent]
    intentValues.foreach { intentIns =>
      var explicit = false
      var precise = true
      var componentNames = isetEmpty[String]
      val iFieldSlot = FieldSlot(intentIns, AndroidConstants.INTENT_COMPONENT)
      s.pointsToSet(currentContext, iFieldSlot).foreach{ compIns =>
        explicit = true
        val cFieldSlot = FieldSlot(compIns, AndroidConstants.COMPONENT_NAME_CLASS)
        s.pointsToSet(currentContext, cFieldSlot).foreach {
          case instance: PTAConcreteStringInstance =>
            componentNames += instance.string
          case _ => precise = false
        }
      }
      var actions: ISet[String] = isetEmpty[String]
      val acFieldSlot = FieldSlot(intentIns, AndroidConstants.INTENT_ACTION)
      s.pointsToSet(currentContext, acFieldSlot).foreach {
        case instance: PTAConcreteStringInstance =>
          actions += instance.string
        case _ => precise = false
      }

      var categories = isetEmpty[String] // the code to get the valueSet of categories is to be added below
      val categoryFieldSlot = FieldSlot(intentIns, AndroidConstants.INTENT_CATEGORIES)
      s.pointsToSet(currentContext, categoryFieldSlot).foreach{
        case instance: PTAConcreteStringInstance => categories += instance.string
        case _ => precise = false
      }

      var datas: ISet[UriData] = isetEmpty
      val dataFieldSlot = FieldSlot(intentIns, AndroidConstants.INTENT_URI_DATA)
      s.pointsToSet(currentContext, dataFieldSlot).foreach{ dataIns =>
        val uriStringFieldSlot = FieldSlot(dataIns, AndroidConstants.URI_STRING)
        s.pointsToSet(currentContext, uriStringFieldSlot).foreach {
          case instance: PTAConcreteStringInstance =>
            val uriString = instance.string
            var uriData = new UriData
            populateByUri(uriData, uriString)
            datas += uriData
          case _ => precise = false
        }
      }

      var types:Set[String] = Set()
      val mtypFieldSlot = FieldSlot(intentIns, AndroidConstants.INTENT_MTYPE)
      s.pointsToSet(currentContext, mtypFieldSlot).foreach {
        case instance: PTAConcreteStringInstance => types += instance.string
        case _ => precise = false
      }
      val ic = Intent(componentNames, actions, categories, datas, types)
      ic.explicit = explicit
      ic.precise = precise
      result += ic
    }
    result
  }

  def populateByUri(data: UriData, uriData: String): Unit = {
    var scheme:String = null
    var host:String = null
    var port:String = null
    var path:String = null
    if(uriData != null){
      if(!uriData.startsWith("tel:") && !uriData.startsWith("file:") && uriData.contains("://") && uriData.indexOf("://") < uriData.length()) {
        var legalUriStr: String = uriData
        if(uriData.contains("=")){
          val (head, query) = uriData.splitAt(uriData.indexOf("=") + 1)
          legalUriStr = head + URLEncoder.encode(query, "UTF-8")
        }
        try{
          val uri = URI.create(legalUriStr)
          scheme = uri.getScheme
          host = uri.getHost
          port = if(uri.getPort != -1) uri.getPort.toString else null
          path = if(uri.getPath != "") uri.getPath else null
          data.set(scheme, host, port, path, null, null)
        } catch {
          case _: IllegalArgumentException => // err_msg_normal(TITLE, "Unexpected uri: " + legalUriStr)
        }
      } else if(uriData.contains(":")){  // because e.g. app code can have intent.setdata("http:") instead of intent.setdata("http://xyz:200/pqr/abc")
        scheme = uriData.split(":")(0)
        if(scheme != null)
          data.setScheme(scheme)
      }
    }
  }

  def mappingIntents(apk: ApkGlobal, intentContents: ISet[Intent], compType: AndroidConstants.CompType.Value): IMap[Intent, ISet[JawaType]] = {
    intentContents.map{ ic =>
      val components: MSet[JawaType] = msetEmpty
      if(ic.explicit && !ic.precise){
        compType match {
          case AndroidConstants.CompType.ACTIVITY =>
            components ++= apk.model.getActivities
          case AndroidConstants.CompType.SERVICE =>
            components ++= apk.model.getServices
          case AndroidConstants.CompType.RECEIVER =>
            components ++= apk.model.getReceivers
          case AndroidConstants.CompType.PROVIDER =>
            components ++= apk.model.getProviders
        }
      } else if(!ic.explicit && !ic.precise) {
        compType match {
          case AndroidConstants.CompType.ACTIVITY =>
            components ++= apk.model.getActivities.filter(ep => apk.model.getIntentFilterDB.getIntentFilters(ep).nonEmpty)
          case AndroidConstants.CompType.SERVICE =>
            components ++= apk.model.getServices.filter(ep => apk.model.getIntentFilterDB.getIntentFilters(ep).nonEmpty)
          case AndroidConstants.CompType.RECEIVER =>
            components ++= apk.model.getReceivers.filter(ep => apk.model.getIntentFilterDB.getIntentFilters(ep).nonEmpty)
          case AndroidConstants.CompType.PROVIDER =>
            components ++= apk.model.getProviders.filter(ep => apk.model.getIntentFilterDB.getIntentFilters(ep).nonEmpty)
        }
      }
      ic.componentNames.foreach{ targetRecName =>
        val targetRec = apk.getClassOrResolve(new JawaType(targetRecName))
        components += targetRec.getType
      }
      components ++= findComponents(apk, ic.actions, ic.categories, ic.data, ic.types)
      (ic, components.toSet)
    }.toMap
  }

  def findComponents(apk: ApkGlobal, actions: Set[String], categories: Set[String], datas: Set[UriData], mTypes:Set[String]): ISet[JawaType] = {
    val components: MSet[JawaType] = msetEmpty
    if(actions.isEmpty){
      if(datas.isEmpty){
        if(mTypes.isEmpty) components ++= findComps(apk, null, categories, null, null) 
        else mTypes.foreach{components ++= findComps(apk, null, categories, null, _)}
      } else {
        datas.foreach{
          data =>
            if(mTypes.isEmpty) components ++= findComps(apk, null, categories, data, null) 
            else mTypes.foreach{components ++= findComps(apk, null, categories, data, _)}
        }
      }
    } else {  
      actions.foreach{ action =>
        if(datas.isEmpty){
          if(mTypes.isEmpty) components ++= findComps(apk, action, categories, null, null)
          else mTypes.foreach{components ++= findComps(apk, action, categories, null, _)}
        } else {
          datas.foreach{ data =>
            if(mTypes.isEmpty) components ++= findComps(apk, action, categories, data, null)
            else mTypes.foreach{components ++= findComps(apk, action, categories, data, _)}
          }
        }
      }
    }
    components.toSet
  }
  
  private def findComps(apk: ApkGlobal, action:String, categories: Set[String], data:UriData, mType:String): ISet[JawaType] = {
    val components: MSet[JawaType] = msetEmpty
    apk.model.getComponents.foreach { ep =>
      val iFilters = apk.model.getIntentFilterDB.getIntentFilters(ep)
      if(iFilters.nonEmpty){
        val matchedFilters = iFilters.filter(iFilter => iFilter.isMatchWith(action, categories, data, mType))
        if(matchedFilters.nonEmpty)
          components += ep
      }
    }
    components.toSet
  }
}
