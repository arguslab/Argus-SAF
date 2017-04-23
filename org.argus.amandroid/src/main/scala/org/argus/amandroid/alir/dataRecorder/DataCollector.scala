/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.dataRecorder

import java.util

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.InterComponentCommunicationModel
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.core.util._
import org.stringtemplate.v4.STGroupString
import org.argus.amandroid.core.parser.{ComponentType, IntentFilter, UriData}
import org.argus.jawa.alir.{AlirEdge, Context, InterProceduralNode}
import org.argus.jawa.alir.controlFlowGraph.ICFGCallNode
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.VarSlot
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.compiler.parser.CallStatement
import org.argus.jawa.core.Signature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object DataCollector {
  
  private val template = new STGroupString(AppDataStg.getStg)
  
  private def getIntentFilterStrings(intentFilters: ISet[IntentFilter]): util.ArrayList[String] = {
    val intFs: util.ArrayList[String] = new util.ArrayList[String]
    intentFilters.foreach{
      intfilter =>
        val intF = template.getInstanceOf("IntentFilter")
        val actions = intfilter.getActions
        if(actions.nonEmpty){
          val actionStrings: util.ArrayList[String] = new util.ArrayList[String]
          actions.foreach(f=>actionStrings.add(f))
          intF.add("actions", actionStrings)
        }
        val categories = intfilter.getCategorys
        if(categories.nonEmpty){
          val categoryStrings: util.ArrayList[String] = new util.ArrayList[String]
          categories.foreach(f=>categoryStrings.add(f))
          intF.add("categories", categoryStrings)
        }
        val data = intfilter.getData
        if(!data.isEmpty){
          val dataT = template.getInstanceOf("Data")
          val schemes = data.getSchemes
          if(schemes.nonEmpty){
            val schemeStrings: util.ArrayList[String] = new util.ArrayList[String]
            schemes.foreach(f=>schemeStrings.add(f))
            dataT.add("schemes", schemeStrings)
          }
          val authorities = data.getAuthorities
          if(authorities.nonEmpty){
            val hostStrings: util.ArrayList[String] = new util.ArrayList[String]
            val portStrings: util.ArrayList[String] = new util.ArrayList[String]
            authorities.foreach{f=>hostStrings.add(f.host);portStrings.add(f.port)}
            dataT.add("hosts", hostStrings)
            dataT.add("ports", portStrings)
          }
          val paths = data.getPaths
          if(paths.nonEmpty){
            val pathStrings: util.ArrayList[String] = new util.ArrayList[String]
            paths.foreach(f=>pathStrings.add(f))
            dataT.add("paths", pathStrings)
          }
          val pathPrefixs = data.getPathPrefixs
          if(pathPrefixs.nonEmpty){
            val pathPrefixStrings: util.ArrayList[String] = new util.ArrayList[String]
            pathPrefixs.foreach(f=>pathPrefixStrings.add(f))
            dataT.add("pathPrefixs", pathPrefixStrings)
          }
          val pathPatterns = data.getPathPatterns
          if(pathPatterns.nonEmpty){
            val pathPatternStrings: util.ArrayList[String] = new util.ArrayList[String]
            pathPatterns.foreach(f=>pathPatternStrings.add(f))
            dataT.add("pathPatterns", pathPatternStrings)
          }
          val mimeTypes = data.getMimeTypes
          if(mimeTypes.nonEmpty){
            val mimeTypeStrings: util.ArrayList[String] = new util.ArrayList[String]
            mimeTypes.foreach(f=>mimeTypeStrings.add(f))
            dataT.add("mimeTypes", mimeTypeStrings)
          }
          intF.add("data", dataT.render())
        }
        intFs.add(intF.render())
    }
    intFs
  }
  
  final case class AppData(
      name: String, 
      uses_permissions: ISet[String],
      components: ISet[ComponentData],
      taintResultOpt: Option[TaintAnalysisResult[InterProceduralNode, AlirEdge[InterProceduralNode]]]){
    override def toString: String = {
      val appData = template.getInstanceOf("AppData")
      appData.add("name", name)
      val up: util.ArrayList[String] = new util.ArrayList[String]
      uses_permissions.foreach(f=>up.add(f))
      appData.add("uses_permissions", up)
      val comps: util.ArrayList[String] = new util.ArrayList[String]
      components.foreach(f=>comps.add(f.toString))
      appData.add("components", comps)
      val taintResultT = template.getInstanceOf("TaintResult")
      val sourceStrings: util.ArrayList[String] = new util.ArrayList[String]
      if(taintResultOpt.isDefined){
        taintResultOpt.get.getSourceNodes.foreach{
          sn =>
            val ssInfo = template.getInstanceOf("SourceSinkInfo")
            val descriptorStrings: util.ArrayList[String] = new util.ArrayList[String]
            descriptorStrings.add(sn.descriptor.toString)
            ssInfo.add("descriptors", descriptorStrings)
            sourceStrings.add(ssInfo.render())
        }
        val sinkStrings: util.ArrayList[String] = new util.ArrayList[String]
        taintResultOpt.get.getSinkNodes.foreach{
          sn =>
            val ssInfo = template.getInstanceOf("SourceSinkInfo")
            val descriptorStrings: util.ArrayList[String] = new util.ArrayList[String]
            descriptorStrings.add(sn.descriptor.toString)
            ssInfo.add("descriptors", descriptorStrings)
            sinkStrings.add(ssInfo.render())
        }
        taintResultT.add("sources", sourceStrings)
        taintResultT.add("sinks", sinkStrings)
        val pathStrings: util.ArrayList[String] = new util.ArrayList[String]
        val taintPaths = taintResultOpt.get.getTaintedPaths
        taintPaths.foreach{
          taintPath =>
            val path = template.getInstanceOf("TaintPath")
            val sourcessInfo = template.getInstanceOf("SourceSinkInfo")
            val sourceDescriptorStrings: util.ArrayList[String] = new util.ArrayList[String]
            sourceDescriptorStrings.add(taintPath.getSource.descriptor.toString)
            sourcessInfo.add("descriptors", sourceDescriptorStrings)
            path.add("source", sourcessInfo)
            val sinkssInfo = template.getInstanceOf("SourceSinkInfo")
            val sinkDescriptorStrings: util.ArrayList[String] = new util.ArrayList[String]
            sinkDescriptorStrings.add(taintPath.getSink.descriptor.toString)
            sinkssInfo.add("descriptors", sinkDescriptorStrings)
            path.add("sink", sinkssInfo)
            val typStrings: util.ArrayList[String] = new util.ArrayList[String]
            taintPath.getTypes.foreach(f=>typStrings.add(f))
            path.add("typs", typStrings)
            val pathString: util.ArrayList[String] = new util.ArrayList[String]
            val paths = taintPath.getPath
            if(paths.size > 1) {
              paths.tail.foreach{
                edge =>
                  pathString.add(edge.target + "  ->")
              }
              pathString.add(paths.head.source.toString)
            } else if(paths.size == 1) {
              pathString.add(paths.head.target + "  ->")
              pathString.add(paths.head.source.toString)
            }
            path.add("path", pathString)
            pathStrings.add(path.render())
        }
        taintResultT.add("paths", pathStrings)
        appData.add("taintResult", taintResultT)
      }
      appData.render()
    }
  }
  
  final case class IccInfo(
      procs: ISet[Signature],
      context: Context,
      intents: ISet[Intent]){
    override def toString: String = {
      val iccInfo = template.getInstanceOf("IccInfo")
      val procStrings = new util.ArrayList[String]
      procs.foreach{proc => procStrings.add(proc.signature)}
      iccInfo.add("procs", procStrings)
      iccInfo.add("context", context)
      val intentStrings = new util.ArrayList[String]
      intents.foreach(id => intentStrings.add(id.toString))
      iccInfo.add("intents", intentStrings)
      iccInfo.render()
    }
  }
  
  final case class Intent(
      componentNames: ISet[String],
      actions: ISet[String],
      categories: ISet[String],
      uriDatas: ISet[UriData],
      types: ISet[String],
      preciseExplicit: Boolean,
      preciseImplicit: Boolean,
      targets: ISet[(String, String)]){
    val EXPLICIT = "EXPLICIT"
    val IMPLICIT = "IMPLICIT"
    val MIXED = "mixed"
    def getType: String = {
      if(componentNames.nonEmpty && (actions.nonEmpty || categories.nonEmpty || uriDatas.nonEmpty || types.nonEmpty))
        MIXED
      else if(componentNames.nonEmpty) EXPLICIT
      else IMPLICIT
    }
    override def toString: String = {
      val intent = template.getInstanceOf("Intent")
      if(componentNames.nonEmpty){
        val componentNameStrings = new util.ArrayList[String]
        componentNames.foreach(componentNameStrings.add)
        intent.add("componentNames", componentNameStrings)
      }
      if(actions.nonEmpty){
        val actionStrings = new util.ArrayList[String]
        actions.foreach(actionStrings.add)
        intent.add("actions", actionStrings)
      }
      if(categories.nonEmpty){
        val categoryStrings = new util.ArrayList[String]
        categories.foreach(categoryStrings.add)
        intent.add("categories", categoryStrings)
      }
      if(uriDatas.nonEmpty){
        val dataStrings = new util.ArrayList[String]
        uriDatas.foreach{
          data =>
            val uriData = template.getInstanceOf("UriData")
            val scheme = data.getScheme
            if(scheme != null){
              uriData.add("scheme", scheme)
            }
            val host = data.getHost
            if(host != null){
              uriData.add("host", host)
            }
            val port = data.getPort
            if(port != null){
              uriData.add("port", port)
            }
            val path = data.getPath
            if(path != null){
              uriData.add("path", path)
            }
            val pathPrefix = data.getPathPrefix
            if(pathPrefix != null){
              uriData.add("pathPrefix", pathPrefix)
            }
            val pathPattern = data.getPathPattern
            if(pathPattern != null){
              uriData.add("pathPattern", pathPattern)
            }
            dataStrings.add(uriData.render())
        }
        intent.add("datas", dataStrings)
      }
      if(types.nonEmpty){
        val typeStrings = new util.ArrayList[String]
        types.foreach(typeStrings.add)
        intent.add("typs", typeStrings)
      }
      val targetStrings = new util.ArrayList[String]
      targets.foreach{
        case (proc, typ) =>
          val target = template.getInstanceOf("Target")
          target.add("proc", proc)
          target.add("typ", typ)
          targetStrings.add(target.render())
      }
      intent.add("targets", targetStrings)
      intent.render()
    }
  }
     
  final case class ComponentData(
      name: String,
      typ: ComponentType.Value,
      exported: Boolean,
      dynamicReg: Boolean,
      protectPermission: ISet[String],
      intentFilters: ISet[IntentFilter],
      iccInfos: ISet[IccInfo]){
    override def toString: String = {
      val compData = template.getInstanceOf("ComponentData")
      compData.add("compName", name)
      val typstr = typ match {
        case ComponentType.ACTIVITY => "activity"
        case ComponentType.SERVICE => "service"
        case ComponentType.RECEIVER => "receiver"
        case ComponentType.PROVIDER => "provider"
      }
      compData.add("typ", typstr)
      compData.add("exported", exported)
      compData.add("dynamicReg", dynamicReg)
      val permissions = new util.ArrayList[String]
      import collection.JavaConverters._
      permissions.asScala ++= protectPermission
      compData.add("protectPermission", permissions)
      compData.add("intentFilters", getIntentFilterStrings(intentFilters))
      val iccInfoStrings = new util.ArrayList[String]
      iccInfos.foreach(iccinfo => iccInfoStrings.add(iccinfo.toString))
      compData.add("iccInfos", iccInfoStrings)
      compData.render()
    }
  }
  
  def collect(apk: ApkGlobal): AppData = {
    val appName = apk.model.getAppName
    val uses_permissions = apk.model.getUsesPermissions
    val compInfos = apk.model.getComponentInfos
    val intentFDB = apk.model.getIntentFilterDB
    val compDatas = compInfos.map{
      comp =>
        val compTyp = comp.compType
        val compRec = apk.getClassOrResolve(compTyp)
        val typ = comp.typ
        val exported = comp.exported
        val protectPermission = comp.permission
        val intentFilters = intentFDB.getIntentFilters(compTyp)
        var iccInfos = isetEmpty[IccInfo]
//        var taintResult: Option[TaintAnalysisResult[InterproceduralNode, AlirEdge[InterproceduralNode]]] = None
        if(!compRec.isUnknown){
          if(apk.hasIDFG(compTyp)) {
            val InterproceduralDataFlowGraph(icfg, ptaresult) = apk.getIDFG(compTyp).get
            val iccNodes = icfg.nodes.filter{
              node =>
                node.isInstanceOf[ICFGCallNode] && node.asInstanceOf[ICFGCallNode].getCalleeSet.exists(c => InterComponentCommunicationModel.isIccOperation(c.callee))
            }.map(_.asInstanceOf[ICFGCallNode])
            iccInfos =
              iccNodes.flatMap{ iccNode =>
                apk.getMethod(iccNode.getOwner) match {
                  case Some(iccMethod) =>
                    val args = iccMethod.getBody.resolvedBody.locations(iccNode.locIndex).statement.asInstanceOf[CallStatement].args
                    val intentSlot = VarSlot(args.head, isBase = false, isArg = true)
                    val intentValues = ptaresult.pointsToSet(intentSlot, iccNode.context)
                    val intentcontents = IntentHelper.getIntentContents(ptaresult, intentValues, iccNode.getContext)
                    val compType = AndroidConstants.getIccCallType(iccNode.getCalleeSet.head.callee.getSubSignature)
                    val comMap = IntentHelper.mappingIntents(apk, intentcontents, compType)
                    val intents = intentcontents.map(ic=>Intent(ic.componentNames, ic.actions, ic.categories, ic.datas, ic.types, ic.preciseExplicit, ic.preciseImplicit, comMap(ic).map(c=>(c._1.name, c._2.toString))))
                    Some(IccInfo(iccNode.getCalleeSet.map(_.callee), iccNode.getContext, intents))
                  case None => None
                }
              }.toSet
          }
      }
      val dynamicReg = apk.model.getDynamicRegisteredReceivers.contains(compTyp)
      ComponentData(compTyp.jawaName, typ, exported, dynamicReg, protectPermission, intentFilters, iccInfos)
    }
    val taintResult: Option[TaintAnalysisResult[InterProceduralNode, AlirEdge[InterProceduralNode]]] = apk.getTaintAnalysisResult[InterProceduralNode, AlirEdge[InterProceduralNode]](apk.nameUri) match {
      case a @ Some(_) => a
      case None => None
    }
    AppData(appName, uses_permissions, compDatas, taintResult)
  }
}
