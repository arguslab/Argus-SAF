/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli

import java.io._

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.saf.cli.util.CliLogger
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.core._
import org.sireum.util._


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object GenGraph {

  object GraphFormat extends Enumeration {
    val GraphML, GML = Value
  }

  object GraphType extends Enumeration {
    val FULL, SIMPLE_CALL, DETAILED_CALL, API = Value
  }

//  private final val TITLE = "GenCallGraph"
  
  def apply(format: GraphFormat.Value, graphtyp: GraphType.Value, debug: Boolean, header: String, sourcePath: String, outputPath: String) {
    val apkFileUris: MSet[FileResourceUri] = msetEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        apkFileUris ++= ApkFileUtil.getApks(FileUtil.toUri(dir))
      case file =>
        if(ApkGlobal.isValidApk(FileUtil.toUri(file)))
          apkFileUris += FileUtil.toUri(file)
        else println(file + " is not decompilable.")
    }
    genGraph(apkFileUris.toSet, outputPath, header, format, graphtyp, debug)
  }
  
  def genGraph(
      apkFileUris: Set[FileResourceUri],
      outputPath: String,
      header: String,
      format: GraphFormat.Value,
      graphtyp: GraphType.Value,
      debug: Boolean): Unit = {
    println("Total apks: " + apkFileUris.size)
    var i: Int = 0
    apkFileUris.foreach{
      apkFileUri =>
        try{
          i+=1
          println("Analyzing #" + i + ":" + apkFileUri)
          val outputUri = FileUtil.toUri(outputPath)
          val reporter =
            if(debug) new FileReporter(getOutputDirUri(outputUri, apkFileUri), MsgLevel.INFO)
            else new NoReporter
          val yard = new ApkYard(reporter)
          val layout = DecompileLayout(outputUri)
          val settings = DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = true, layout)
          val apk = yard.loadApk(apkFileUri, settings)
          val pros = apk.model.getEntryPoints.flatMap{ compName =>
            val comp = apk.resolveToBody(compName)
            val procedures = comp.getDeclaredMethodsByName(AndroidConstants.MAINCOMP_ENV) ++ comp.getDeclaredMethodsByName(AndroidConstants.COMP_ENV)
            procedures
          }

          val icfg = InterproceduralSuperSpark(apk, pros.map(_.getSignature)).icfg
          val apkName = apkFileUri.substring(apkFileUri.lastIndexOf("/") + 1, apkFileUri.lastIndexOf("."))
          graphtyp match{
            case GraphType.FULL =>
              val graph = icfg
              val ext = format match {
                case GraphFormat.GraphML => ".graphml"
                case GraphFormat.GML => ".gml"
              }
              val file = FileUtil.toFile(apk.model.outApkUri + "/" + apkName.filter(_.isUnicodeIdentifierPart) + ext)
              val w = new FileOutputStream(file)
              val zips = new BufferedOutputStream(w)
              val zipw = new BufferedWriter(new OutputStreamWriter(zips, "UTF-8"))
              try {
                format match {
                  case GraphFormat.GraphML => graph.toGraphML(zipw)
                  case GraphFormat.GML => graph.toGML(zipw)
                }
              } catch {case _: Exception => }
              finally {
                zipw.close()
              }
            case GraphType.SIMPLE_CALL =>
              val path = new File(outputPath + "/" + apkName.filter(_.isUnicodeIdentifierPart) + "/simple_cg")
              val fm = format match {
                case GraphFormat.GraphML => "GraphML"
                case GraphFormat.GML => "GML"
              }
              icfg.getCallGraph.storeSimpleCallGraph(apk.nameUri, header, path.getPath, fm)
            case GraphType.DETAILED_CALL =>
              val path = new File(outputPath + "/" + apkName.filter(_.isUnicodeIdentifierPart) + "/detailed_cg")
              val fm = format match {
                case GraphFormat.GraphML => "GraphML"
                case GraphFormat.GML => "GML"
              }
              icfg.getCallGraph.storeDetailedCallGraph(header, icfg, path.getPath, fm)
            case GraphType.API =>
              val graph = icfg.toApiGraph(apk)
              val ext = format match {
                case GraphFormat.GraphML => ".graphml"
                case GraphFormat.GML => ".gml"
              }
              val file = FileUtil.toFile(apk.model.outApkUri + "/" + apkName.filter(_.isUnicodeIdentifierPart) + ext)
              val w = new FileOutputStream(file)
              val zips = new BufferedOutputStream(w)
              val zipw = new BufferedWriter(new OutputStreamWriter(zips, "UTF-8"))
              try {
                format match {
                  case GraphFormat.GraphML => graph.toGraphML(zipw)
                  case GraphFormat.GML => graph.toGML(zipw)
                }
              } catch {case _: Exception =>}
              finally {
                zipw.close()
              }
          }
          println(apkName + " result stored!")
          if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
          println("Done!")
       } catch {
         case e: Throwable =>
           CliLogger.logError(new File(outputPath), "Error: " , e)
       } finally {
         // before starting the analysis of the current app, first clear the previous app's records' code from the AmandroidCodeSource
         System.gc()
       }
    }
  }
  private def getOutputDirUri(outputUri: FileResourceUri, apkUri: FileResourceUri): FileResourceUri = {
    outputUri + {if(!outputUri.endsWith("/")) "/" else ""} + apkUri.substring(apkUri.lastIndexOf("/") + 1, apkUri.lastIndexOf("."))
  }
}