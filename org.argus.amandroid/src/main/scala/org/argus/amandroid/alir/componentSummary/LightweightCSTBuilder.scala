/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import org.argus.jawa.core.util._
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper.IntentContent
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.parser.{ComponentType, UriData}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGEntryNode, ICFGExitNode}
import org.argus.jawa.alir.dataFlowAnalysis.InterProceduralDataFlowGraph
import org.argus.jawa.alir.pta.{ClassInstance, Instance, PTAConcreteStringInstance, VarSlot}
import org.argus.jawa.alir.pta.suspark.InterProceduralSuperSpark
import org.argus.jawa.core.{Global, JavaKnowledge, JawaType, Signature}

/**
 * Hopefully this will be really light weight to build the component based summary table
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class LightweightCSTBuilder(global: Global) {
  
  private val intentContents: MMap[JawaType, MMap[Instance, MSet[IntentContent]]] = mmapEmpty
  private val summaryTables: MMap[JawaType, ComponentSummaryTable] = mmapEmpty
  
  def getSummaryTables: IMap[JawaType, ComponentSummaryTable] = summaryTables.toMap
  
  def build(yard: ApkYard, apk: ApkGlobal, comps: ISet[(JawaType, ComponentType.Value)]): Unit = {
    println("Total components: " + comps.size)
    var i = 0
    comps foreach {
      case (compTyp, _) =>
        val comp = global.getClassOrResolve(compTyp)
        val methods = comp.getDeclaredMethods.filter(m => m.isConcrete && !m.isPrivate)
        println("methods: " + methods.size)
        val idfg = InterProceduralSuperSpark(global, methods.map(_.getSignature))
        val context = new Context(apk.nameUri)
        val sig = new Signature(JavaKnowledge.formatTypeToSignature(comp.getType) + ".ent:()V")
        context.setContext(sig, compTyp.name)
        val entryNode = ICFGEntryNode(context)
        entryNode.setOwner(sig)
        idfg.icfg.addEntryNode(entryNode)
        val exitNode = ICFGExitNode(context)
        exitNode.setOwner(sig)
        idfg.icfg.addExitNode(exitNode)
        apk.addIDFG(compTyp, idfg)
        collectIntentContent(compTyp, idfg)
        buildCSTFromIDFG(apk, compTyp, idfg)
        i += 1
        println("components resolved: " + i)
    }
  }
  
  private def collectIntentContent(componentType: JawaType, idfg: InterProceduralDataFlowGraph) = {
    val cpIntentmap = intentContents.getOrElseUpdate(componentType, mmapEmpty)
    val allIntent = msetEmpty[Instance]
    val impreciseExplicit = msetEmpty[Instance]
    val impreciseImplicit = msetEmpty[Instance]
    val componentNames = mmapEmpty[Instance, MSet[String]]
    val actions = mmapEmpty[Instance, MSet[String]]
    val categories = mmapEmpty[Instance, MSet[String]]
    val datas = mmapEmpty[Instance, MSet[UriData]]
    val types = mmapEmpty[Instance, MSet[String]]
    val unresolvedData = mmapEmpty[Instance, MSet[Instance]]
    val unresolvedComp = mmapEmpty[Instance, MSet[Instance]]
    
    val icfg = idfg.icfg
    val ptaresult = idfg.ptaresult
    icfg.nodes.foreach {
      case cn: ICFGCallNode =>
        val callees = cn.getCalleeSet
        val args = cn.argNames
        val currentContext = cn.context
        callees foreach {
          callee =>
            callee.callee.signature match {
              case "Landroid/content/Intent;.<init>:(Landroid/content/Context;Ljava/lang/Class;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val param2Slot = VarSlot(args(2), isBase = false, isArg = true)
                val param2Value = ptaresult.pointsToSet(param2Slot, currentContext)
                param2Value.map {
                  case ci: ClassInstance =>
                    val componentName = ci.getName
                    thisValue.map(componentNames.getOrElseUpdate(_, msetEmpty) += componentName)
                  case _ => impreciseExplicit ++= thisValue
                }
              case "Landroid/content/Intent;.<init>:(Landroid/content/Intent;)V" => //public constructor
              case "Landroid/content/Intent;.<init>:(Landroid/content/Intent;Z)V" => //private constructor
              case "Landroid/content/Intent;.<init>:(Ljava/lang/String;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
                val actionValue = ptaresult.pointsToSet(actionSlot, currentContext)
                actionValue.foreach {
                  case psi: PTAConcreteStringInstance =>
                    val action = psi.string
                    thisValue.map(actions.getOrElseUpdate(_, msetEmpty) += action)
                  case _ => impreciseImplicit ++= thisValue
                }
              case "Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
                val actionValue = ptaresult.pointsToSet(actionSlot, currentContext)
                val dataSlot = VarSlot(args(2), isBase = false, isArg = true)
                val dataValue = ptaresult.pointsToSet(dataSlot, currentContext)
                actionValue.foreach {
                  case psi: PTAConcreteStringInstance =>
                    val action = psi.string
                    thisValue.map(actions.getOrElseUpdate(_, msetEmpty) += action)
                  case _ => impreciseImplicit ++= thisValue
                }
                thisValue.map(unresolvedData.getOrElseUpdate(_, msetEmpty) ++= dataValue)
              case "Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;Landroid/content/Context;Ljava/lang/Class;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
                val actionValue = ptaresult.pointsToSet(actionSlot, currentContext)
                val dataSlot = VarSlot(args(2), isBase = false, isArg = true)
                val dataValue = ptaresult.pointsToSet(dataSlot, currentContext)
                val classSlot = VarSlot(args(4), isBase = false, isArg = true)
                val classValue = ptaresult.pointsToSet(classSlot, currentContext)
                actionValue.foreach {
                  case psi: PTAConcreteStringInstance =>
                    val action = psi.string
                    thisValue.map(actions.getOrElseUpdate(_, msetEmpty) += action)
                  case _ => impreciseImplicit ++= thisValue
                }
                thisValue.map(unresolvedData.getOrElseUpdate(_, msetEmpty) ++= dataValue)
                classValue.map {
                  case ci: ClassInstance =>
                    val componentName = ci.getName
                    thisValue.map(componentNames.getOrElseUpdate(_, msetEmpty) += componentName)
                  case _ => impreciseExplicit ++= thisValue
                }
              case "Landroid/content/Intent;.addCategory:(Ljava/lang/String;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val categorySlot = VarSlot(args(1), isBase = false, isArg = true)
                val categoryValue = ptaresult.pointsToSet(categorySlot, currentContext)
                categoryValue.foreach {
                  case psi: PTAConcreteStringInstance =>
                    val category = psi.string
                    thisValue.map(categories.getOrElseUpdate(_, msetEmpty) += category)
                  case _ => impreciseImplicit ++= thisValue
                }
              case "Landroid/content/Intent;.addFlags:(I)Landroid/content/Intent;" => //public
              case "Landroid/content/Intent;.setAction:(Ljava/lang/String;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
                val actionValue = ptaresult.pointsToSet(actionSlot, currentContext)
                actionValue.foreach {
                  case psi: PTAConcreteStringInstance =>
                    val action = psi.string
                    thisValue.map(actions.getOrElseUpdate(_, msetEmpty) += action)
                  case _ => impreciseImplicit ++= thisValue
                }
              case "Landroid/content/Intent;.setClass:(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val classSlot = VarSlot(args(2), isBase = false, isArg = true)
                val classValue = ptaresult.pointsToSet(classSlot, currentContext)
                classValue.map {
                  case ci: ClassInstance =>
                    val componentName = ci.getName
                    thisValue.map(componentNames.getOrElseUpdate(_, msetEmpty) += componentName)
                  case _ => impreciseExplicit ++= thisValue
                }
              case "Landroid/content/Intent;.setClassName:(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;" |
                   "Landroid/content/Intent;.setClassName:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val classSlot = VarSlot(args(2), isBase = false, isArg = true)
                val classValue = ptaresult.pointsToSet(classSlot, currentContext)
                classValue.map {
                  case psi: PTAConcreteStringInstance =>
                    val componentName = psi.string
                    thisValue.map(componentNames.getOrElseUpdate(_, msetEmpty) += componentName)
                  case _ => impreciseExplicit ++= thisValue
                }
              case "Landroid/content/Intent;.setComponent:(Landroid/content/ComponentName;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val componentSlot = VarSlot(args(1), isBase = false, isArg = true)
                val componentValue = ptaresult.pointsToSet(componentSlot, currentContext)
                thisValue.map(unresolvedComp.getOrElseUpdate(_, msetEmpty) ++= componentValue)
              case "Landroid/content/Intent;.setData:(Landroid/net/Uri;)Landroid/content/Intent;" |
                   "Landroid/content/Intent;.setDataAndNormalize:(Landroid/net/Uri;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val dataSlot = VarSlot(args(1), isBase = false, isArg = true)
                val dataValue = ptaresult.pointsToSet(dataSlot, currentContext)
                thisValue.map(unresolvedData.getOrElseUpdate(_, msetEmpty) ++= dataValue)
              case "Landroid/content/Intent;.setDataAndType:(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;" |
                   "Landroid/content/Intent;.setDataAndTypeAndNormalize:(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val dataSlot = VarSlot(args(1), isBase = false, isArg = true)
                val dataValue = ptaresult.pointsToSet(dataSlot, currentContext)
                val typeSlot = VarSlot(args(2), isBase = false, isArg = true)
                val typeValue = ptaresult.pointsToSet(typeSlot, currentContext)
                thisValue.map(unresolvedData.getOrElseUpdate(_, msetEmpty) ++= dataValue)
                typeValue.map {
                  case psi: PTAConcreteStringInstance =>
                    val typeName = psi.string
                    thisValue.map(types.getOrElseUpdate(_, msetEmpty) += typeName)
                  case _ => impreciseImplicit ++= thisValue
                }
              case "Landroid/content/Intent;.setFlags:(I)Landroid/content/Intent;" => //public
              case "Landroid/content/Intent;.setPackage:(Ljava/lang/String;)Landroid/content/Intent;" => //public
              case "Landroid/content/Intent;.setType:(Ljava/lang/String;)Landroid/content/Intent;" |
                   "Landroid/content/Intent;.setTypeAndNormalize:(Ljava/lang/String;)Landroid/content/Intent;" => //public
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                allIntent ++= thisValue
                val typeSlot = VarSlot(args(1), isBase = false, isArg = true)
                val typeValue = ptaresult.pointsToSet(typeSlot, currentContext)
                typeValue.map {
                  case psi: PTAConcreteStringInstance =>
                    val typeName = psi.string
                    thisValue.map(types.getOrElseUpdate(_, msetEmpty) += typeName)
                  case _ => impreciseImplicit ++= thisValue
                }
              case _ =>
            }
        }
      case _ =>
    }
    
    icfg.nodes.foreach {
      case cn: ICFGCallNode =>
        val callees = cn.getCalleeSet
        val args = cn.argNames
        val rets = cn.retNameOpt ++ List("hack") // for safety
        val currentContext = cn.context
        callees foreach {
          callee =>
            callee.callee.signature match {
              case "Landroid/net/Uri;.parse:(Ljava/lang/String;)Landroid/net/Uri;" => //public static
                val strSlot = VarSlot(args.head, isBase = false, isArg = true)
                val strValue = ptaresult.pointsToSet(strSlot, currentContext)
                val retSlot = VarSlot(rets.head, isBase = false, isArg = false)
                val retValue = ptaresult.pointsToSet(retSlot, currentContext)
                unresolvedData.foreach {
                  case (intent, ds) =>
                    if (ds.intersect(retValue).nonEmpty) {
                      strValue.foreach {
                        case PTAConcreteStringInstance(text, _) =>
                          val data = new UriData
                          IntentHelper.populateByUri(data, text)
                          datas.getOrElseUpdate(intent, msetEmpty) += data
                        case _ => impreciseImplicit += intent
                      }
                    }
                }
              case "Landroid/content/ComponentName;.<init>:(Landroid/content/Context;Ljava/lang/Class;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                val componentSlot = VarSlot(args(2), isBase = false, isArg = true)
                val componentValue = ptaresult.pointsToSet(componentSlot, currentContext)
                unresolvedComp.foreach {
                  case (intent, comps) =>
                    if (comps.intersect(thisValue).nonEmpty) {
                      componentValue.foreach {
                        case ci: ClassInstance =>
                          val component = ci.getName
                          componentNames.getOrElseUpdate(intent, msetEmpty) += component
                        case _ => impreciseImplicit += intent
                      }
                    }
                }
              case "Landroid/content/ComponentName;.<init>:(Landroid/content/Context;Ljava/lang/String;)V" |
                   "Landroid/content/ComponentName;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" => //public constructor
                val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
                val thisValue = ptaresult.pointsToSet(thisSlot, currentContext)
                val componentSlot = VarSlot(args(2), isBase = false, isArg = true)
                val componentValue = ptaresult.pointsToSet(componentSlot, currentContext)
                unresolvedComp.foreach {
                  case (intent, comps) =>
                    if (comps.intersect(thisValue).nonEmpty) {
                      componentValue.foreach {
                        case PTAConcreteStringInstance(text, _) =>
                          val component = text
                          componentNames.getOrElseUpdate(intent, msetEmpty) += component
                        case _ => impreciseImplicit += intent
                      }
                    }
                }
              case "Landroid/content/ComponentName;.<init>:(Landroid/os/Parcel;)V" => //public constructor
              case "Landroid/content/ComponentName;.<init>:(Ljava/lang/String;Landroid/os/Parcel;)V" => //private constructor
              case _ =>
            }
        }
      case _ =>
    }
    
    allIntent.foreach {
      intent =>
        val comps: ISet[String] = componentNames.getOrElse(intent, msetEmpty).toSet
        val acs: ISet[String] = actions.getOrElse(intent, msetEmpty).toSet
        val cas: ISet[String] = categories.getOrElse(intent, msetEmpty).toSet
        val das: ISet[UriData] = datas.getOrElse(intent, msetEmpty).toSet
        val tys: ISet[String] = types.getOrElse(intent, msetEmpty).toSet
        val preciseExplicit: Boolean = !impreciseExplicit.contains(intent)
        val preciseImplicit: Boolean = !impreciseImplicit.contains(intent)
        cpIntentmap.getOrElseUpdate(intent, msetEmpty) += IntentContent(comps, acs, cas, das, tys, preciseExplicit, preciseImplicit)
    }
  }
  
  private def buildCSTFromIDFG(apk: ApkGlobal, componentType: JawaType, idfg: InterProceduralDataFlowGraph) = {
    val summaryTable = ComponentSummaryTable.buildComponentSummaryTable(Component(apk, componentType), idfg)
    summaryTables(componentType) = summaryTable
  }
}
