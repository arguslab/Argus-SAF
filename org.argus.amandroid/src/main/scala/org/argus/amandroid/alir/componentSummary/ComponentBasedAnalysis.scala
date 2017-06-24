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
import java.util.concurrent.TimeoutException

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidRFAConfig, AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, AndroidSourceAndSinkManager}
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.dataDependenceAnalysis._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.SimHeap
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.util.{MyTimeout, WorklistAlgorithm}
import org.argus.jawa.core.{ClassLoadManager, JawaType}

import scala.compat.Platform.EOL
import scala.concurrent.duration._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ComponentBasedAnalysis {
  private final val TITLE = "ComponentBasedAnalysis"
  private final val DEBUG = false
  def prepare(apks: ISet[ApkGlobal])(implicit timeout: FiniteDuration): Unit = {
    AndroidReachingFactsAnalysisConfig.resolve_icc = false // We don't want to resolve ICC at this phase
    apks.foreach { apk =>
      println("Prepare IDFGs for: " + apk.model.getAppName)
      var components = apk.model.getComponents
      val worklist = new WorklistAlgorithm[JawaType] {
        override def processElement(component: JawaType): Unit = {
          println("--Analyzing component: " + component)
          try {
            apk.model.getEnvMap.get(component) match {
              case Some((esig, _)) =>
                val ep = apk.getMethod(esig).get
                implicit val factory = new SimHeap
                val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(ep)
                val idfg = AndroidReachingFactsAnalysis(apk, ep, initialfacts, new ClassLoadManager, new Context(apk.nameUri), timeout = Some(new MyTimeout(timeout)))
                idfg.ptaresult.pprint(false)
                apk.addIDFG(component, idfg)
              case None =>
                apk.reporter.error(TITLE, "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest.")
            }
          } catch {
            case te: TimeoutException => // Timeout happened
              apk.reporter.error(TITLE, component + " " + te.getMessage)
            case ex: Exception =>
              if (DEBUG) ex.printStackTrace()
              apk.reporter.error(TITLE, "Analyzing component " + component + " has error: " + ex.getMessage + "\n" + ex.getStackTrace.mkString("", EOL, EOL))
          } finally {
            System.gc()
          }
          worklist = (apk.model.getComponents -- components) ++: worklist
          components = apk.model.getComponents
        }
      }
      worklist.run(worklist.worklist = components.toList)
    }
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ComponentBasedAnalysis(yard: ApkYard) {
  import ComponentBasedAnalysis._
  
  val problematicComp: MMap[FileResourceUri, MSet[JawaType]] = mmapEmpty
  
  /**
   * ComponentBasedAnalysis phase1 is doing intra component analysis for one giving apk.
   */
  def phase1(apks: ISet[ApkGlobal]): Unit = {
    println(TITLE + ":" + " Phase 1:")
    apks.foreach { apk =>
      println("--Analyzing " + apk.model.getAppName)
      val idfgs = apk.getIDFGs
      idfgs foreach { case (comp, idfg) =>
        println("----Data Dependence Analysis: " + comp)
        // do dda on this component
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        apk.addIDDG(comp, iddResult)
      }
      var components = apk.model.getComponents
      problematicComp.getOrElseUpdate(apk.nameUri, msetEmpty) ++= (components -- idfgs.keySet)
      components = components -- problematicComp(apk.nameUri)

      components.foreach { component =>
        println("----Building ST for component: " + component)
        try {
          // build summary table
          val summaryTable = buildComponentSummaryTable(Component(apk, component))
          apk.addSummaryTable(component, summaryTable)
        } catch {
          case ex: Exception =>
            problematicComp(apk.nameUri) += component
            if (DEBUG) ex.printStackTrace()
            yard.reporter.error(TITLE, "Collect Info for Component " + component + " has error: " + ex.getMessage)
        }
      }
    }
  }
  
  def phase2(apks: ISet[ApkGlobal]): (ISet[ApkGlobal], InterProceduralDataDependenceInfo) = {
    val components: ISet[Component] = apks.flatMap { apk =>
      (apk.model.getComponents -- problematicComp(apk.nameUri)).map(Component(apk, _))
    }
    println(TITLE + ":" + " Phase 2-------" + apks.size + s" apk${if (apks.size > 1) "s" else ""} " + components.size + s" component${if (components.size > 1) "s" else ""}-------")
    val mddg = ComponentSummaryTable.buildMultiDataDependentGraph(components, yard.reporter)
//    mddg.toDot(new java.io.PrintWriter(System.out))
    (apks, new DefaultInterProceduralDataDependenceInfo(mddg))
  }
  
  def phase3(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), ssm: AndroidSourceAndSinkManager): Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterProceduralDataDependenceAnalysis.Edge]] = {
    val apks = iddResult._1
    val components: ISet[Component] = apks.flatMap { apk =>
      (apk.model.getComponents -- problematicComp(apk.nameUri)).map(Component(apk, _))
    }
    println(TITLE + ":" + " Phase 3-------" + apks.size + s" apk${if(apks.size > 1)"s" else ""} " + components.size + s" component${if(components.size > 1)"s" else ""}-------")
    val idfgs = components.flatMap(component => component.apk.getIDFG(component.typ))
    if(idfgs.nonEmpty) {
      try {
        val ptaresult = idfgs.map(_.ptaresult).reduce(_.merge(_))
        val tar = AndroidDataDependentTaintAnalysis(yard, iddResult._2, ptaresult, ssm)
        yard.setInterAppTaintAnalysisResult(tar)
        apks.foreach(_.addTaintAnalysisResult(tar))
        Some(tar)
      } catch {
        case ex: Exception =>
          if(DEBUG) ex.printStackTrace()
          yard.reporter.error(TITLE, ex.getMessage)
          None
      }
    } else None
  }
  
  private def buildComponentSummaryTable(component: Component): ComponentSummaryTable = {
    val idfgOpt = component.apk.getIDFG(component.typ)
    if(idfgOpt.isEmpty) return new ComponentSummaryTable(component)
    val idfg = idfgOpt.get
    ComponentSummaryTable.buildComponentSummaryTable(component, idfg)
  }
}
