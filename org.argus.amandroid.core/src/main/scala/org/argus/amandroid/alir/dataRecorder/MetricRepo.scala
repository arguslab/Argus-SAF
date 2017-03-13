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

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object MetricRepo {
  /**ICC compare*/
  var iccTotal = 0
  var explicitIccTotal = 0
  var explicitIccPrecise = 0
  var explicitIccTargetFound = 0
  var implicitIccTotal = 0
  var implicitIccPrecise = 0
  var implicitIccTargetFound = 0
  var mixedIccTotal = 0
  var mixedIccPrecise = 0
  var mixedIccTargetFound = 0
  var dynamicRegisteredIccTotal = 0

  /**Security study compare*/
  var activityHijacking = 0
  var serviceHijacking = 0
  var broadcastReceiverTheft = 0
  var contentProviderInfoLeak = 0
  var activityLaunch = 0
  var serviceLaunch = 0
  var broadcastReceiverInjection = 0
  var contentProviderCapabilityLeak = 0
  var maliciousness = 0

  def collect(appData: DataCollector.AppData) = {
    appData.components.foreach{
      comp =>
        val iccInfos = comp.iccInfos
        iccInfos.foreach{
          iccInfo =>
            iccTotal += 1
            val intentDatas = iccInfo.intents
            intentDatas.foreach{
              intentData =>
                intentData.getType match{
                  case intentData.EXPLICIT => 
                    explicitIccTotal += 1
                    if(intentData.preciseExplicit) explicitIccPrecise += 1
                    if(intentData.targets.nonEmpty && intentData.targets.forall(_._2 == intentData.EXPLICIT)) explicitIccTargetFound += 1
                  case intentData.IMPLICIT =>
                    implicitIccTotal += 1
                    if(intentData.preciseImplicit) implicitIccPrecise += 1
                    if(intentData.targets.nonEmpty && intentData.targets.forall(_._2 == intentData.IMPLICIT)) implicitIccTargetFound += 1
                  case intentData.MIXED =>
                    mixedIccTotal += 1
                    if(intentData.preciseExplicit && intentData.preciseImplicit) mixedIccPrecise += 1
                    if(intentData.targets.nonEmpty
                        && intentData.targets.exists(_._2 == intentData.EXPLICIT) 
                        && intentData.targets.exists(_._2 == intentData.IMPLICIT)) mixedIccTargetFound += 1
                }
            }
        }
    }
    appData.components.foreach{
      comp =>
        if(comp.dynamicReg)
          dynamicRegisteredIccTotal += 1
    }
//    appData.components.foreach{
//      comp =>
//        val compType = comp.typ
//        if(comp.taintResultOpt.isDefined){
//          comp.taintResultOpt.get.getTaintedPaths.foreach{
//            tp =>
//              tp.getTypes.foreach{
//                problemType =>
//                  compType match {
//                    case "activity" =>
//                      problemType match{
//                        case AndroidProblemCategories.VUL_INFORMATION_LEAK => activityHijacking += 1
//                        case AndroidProblemCategories.VUL_CAPABILITY_LEAK => activityLaunch += 1
//                        case AndroidProblemCategories.MAL_INFORMATION_LEAK => maliciousness += 1
//                        case AndroidProblemCategories.VUL_CONFUSED_DEPUTY => 
//                      }
//                    case "service" =>
//                      problemType match{
//                        case AndroidProblemCategories.VUL_INFORMATION_LEAK => serviceHijacking += 1
//                        case AndroidProblemCategories.VUL_CAPABILITY_LEAK => serviceLaunch += 1
//                        case AndroidProblemCategories.MAL_INFORMATION_LEAK => maliciousness += 1
//                        case AndroidProblemCategories.VUL_CONFUSED_DEPUTY => 
//                      }
//                    case "receiver" =>
//                      problemType match{
//                        case AndroidProblemCategories.VUL_INFORMATION_LEAK => broadcastReceiverTheft += 1
//                        case AndroidProblemCategories.VUL_CAPABILITY_LEAK => broadcastReceiverInjection += 1
//                        case AndroidProblemCategories.MAL_INFORMATION_LEAK => maliciousness += 1
//                        case AndroidProblemCategories.VUL_CONFUSED_DEPUTY => 
//                      }
//                    case "provider" =>
//                      problemType match{
//                        case AndroidProblemCategories.VUL_INFORMATION_LEAK => contentProviderInfoLeak += 1
//                        case AndroidProblemCategories.VUL_CAPABILITY_LEAK => contentProviderCapabilityLeak += 1
//                        case AndroidProblemCategories.MAL_INFORMATION_LEAK => maliciousness += 1
//                        case AndroidProblemCategories.VUL_CONFUSED_DEPUTY => 
//                      }
//                  }
//              }
//          }
//        }
//    }
  }

  override def toString: String = {
    val sb = new StringBuilder
    sb.append("Total ICC calls: " + this.iccTotal + "\n")
    sb.append("Total explicit ICC calls: " + this.explicitIccTotal + "\n")
    sb.append("Precise explicit ICC calls: " + this.explicitIccPrecise + "  " + {if(this.explicitIccTotal != 0) this.explicitIccPrecise.toFloat/this.explicitIccTotal*100 + "%"} + "\n")
    sb.append("Found explicit ICC targets: " + this.explicitIccTargetFound + "  " + {if(this.explicitIccTotal != 0) this.explicitIccTargetFound.toFloat/this.explicitIccTotal*100 + "%"} + "\n")
    sb.append("Total implicit ICC calls: " + this.implicitIccTotal + "\n")
    sb.append("Precise implicit ICC calls: " + this.implicitIccPrecise + "  " + {if(this.implicitIccTotal != 0) this.implicitIccPrecise.toFloat/this.implicitIccTotal*100 + "%"} + "\n")
    sb.append("Found implicit ICC targets: " + this.implicitIccTargetFound + "  " + {if(this.implicitIccTotal != 0) this.implicitIccTargetFound.toFloat/this.implicitIccTotal*100 + "%"} + "\n")
    sb.append("Total mixed ICC calls: " + this.mixedIccTotal + "\n")
    sb.append("Precise mixed ICC calls: " + this.mixedIccPrecise + "  " + {if(this.mixedIccTotal != 0) this.mixedIccPrecise.toFloat/this.mixedIccTotal*100 + "%"} + "\n")
    sb.append("Found mixed ICC targets: " + this.mixedIccTargetFound + "  " + {if(this.mixedIccTotal != 0) this.mixedIccTargetFound.toFloat/this.mixedIccTotal*100 + "%"} + "\n")
    sb.append("Total dynamic register components: " + this.dynamicRegisteredIccTotal + "\n")
//    sb.append("\n\n")
//    sb.append("Activity Hijacking: " + this.activityHijacking + "\n")
//    sb.append("Service Hijacking: " + this.serviceHijacking + "\n")
//    sb.append("BroadcastReceiver Theft: " + this.broadcastReceiverTheft + "\n")
//    sb.append("ContentProvider Infomation Leak: " + this.contentProviderInfoLeak + "\n")
//    sb.append("Activity Launch: " + this.activityLaunch + "\n")
//    sb.append("Service Launch: " + this.serviceLaunch + "\n")
//    sb.append("BroadcastReceiver Injection: " + this.broadcastReceiverInjection + "\n")
//    sb.append("ContentProvider Capability Leak: " + this.contentProviderCapabilityLeak + "\n")
//    sb.append("Malicious: " + this.maliciousness + "\n")
    sb.toString
  }
}
