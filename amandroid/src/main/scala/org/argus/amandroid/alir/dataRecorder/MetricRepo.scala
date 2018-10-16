/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
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

  def collect(appData: DataCollector.AppData): Unit = {
    appData.components.foreach{ comp =>
      val iccInfos = comp.iccInfos
      iccInfos.foreach{ iccInfo =>
        iccTotal += 1
        val intentDatas = iccInfo.intents
        intentDatas.foreach{ intentData =>
          if(intentData.explicit) {
            explicitIccTotal += 1
            if (intentData.explicit && intentData.precise) explicitIccPrecise += 1
            if (intentData.targets.nonEmpty) explicitIccTargetFound += 1
          } else {
            implicitIccTotal += 1
            if(!intentData.explicit && intentData.precise) implicitIccPrecise += 1
            if(intentData.targets.nonEmpty) implicitIccTargetFound += 1
          }
        }
      }
    }
    appData.components.foreach{ comp =>
      if(comp.dynamicReg)
        dynamicRegisteredIccTotal += 1
    }
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
    sb.append("Total dynamic register components: " + this.dynamicRegisteredIccTotal + "\n")
    sb.toString
  }
}
