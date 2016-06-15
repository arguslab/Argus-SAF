/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf.cli

import java.io._
import java.util.concurrent.TimeoutException

import org.argus.saf.cli.util.CliLogger
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.decompile.ApkDecompiler
import org.argus.amandroid.core.util.{AndroidLibraryAPISummary, ApkFileUtil}
import org.argus.amandroid.core.{AndroidConstants, AndroidGlobalConfig, Apk}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGNode, InterproceduralControlFlowGraph}
import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.core._
import org.argus.jawa.core.util.FutureUtil
import org.sireum.util._

import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.{global => ec}
import scala.concurrent.duration._


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
//    if(args.size != 6){
//      println("Usage: <[Graph Format: DOT, GraphML, GML> <[Graph Type: FULL, SIMPLE_CALL, DETAILED_CALL, API> <debug> <header> <source path> <output path>")
//      return
//    }
    val dpsuri = AndroidGlobalConfig.settings.dependence_dir.map(FileUtil.toUri)
    val liblist = AndroidGlobalConfig.settings.lib_files
    val static = AndroidGlobalConfig.settings.static_init
    val parallel = AndroidGlobalConfig.settings.parallel
    val k_context = AndroidGlobalConfig.settings.k_context
    
    val apkFileUris: MSet[FileResourceUri] = msetEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        apkFileUris ++= ApkFileUtil.getApks(FileUtil.toUri(dir), recursive = true)
      case file =>
        if(Apk.isValidApk(FileUtil.toUri(file)))
          apkFileUris += FileUtil.toUri(file)
        else println(file + " is not decompilable.")
    }
    genGraph(apkFileUris.toSet, outputPath, dpsuri, liblist, static, parallel, k_context, header, format, graphtyp, debug)
  }
  
  def genGraph(
      apkFileUris: Set[FileResourceUri], 
      outputPath: String, 
      dpsuri: Option[FileResourceUri], 
      liblist: String, 
      static: Boolean, 
      parallel: Boolean, 
      k_context: Int,
      header: String,
      format: GraphFormat.Value,
      graphtyp: GraphType.Value,
      debug: Boolean) = {
    Context.init_context_length(k_context)
    println("Total apks: " + apkFileUris.size)
    try{
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
            val global = new Global(apkFileUri, reporter)
            global.setJavaLib(liblist)
            
            val timer = AndroidGlobalConfig.settings.timeout minutes
            val (f, cancel) = FutureUtil.interruptableFuture[(InterproceduralControlFlowGraph[ICFGNode], FileResourceUri)] { () =>
              val (outUri, srcs, _) = ApkDecompiler.decompile(FileUtil.toFile(apkFileUri), FileUtil.toFile(outputUri), dpsuri, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = true)
              srcs foreach {
                src =>
                  val fileUri = FileUtil.toUri(FileUtil.toFilePath(outUri) + File.separator + src)
                  if(FileUtil.toFile(fileUri).exists()) {
                    //store the app's pilar code in AmandroidCodeSource which is organized class by class.
                    global.load(fileUri, Constants.PILAR_FILE_EXT, AndroidLibraryAPISummary)
                  }
              }
              val apk = new Apk(apkFileUri, outUri, srcs)
              AppInfoCollector.collectInfo(apk, global, outUri)
              val eps = apk.getEntryPoints
              val pros =
                eps.map{
                  compName =>
                    val comp = global.resolveToBody(compName)
                    val procedures = comp.getDeclaredMethodsByName(AndroidConstants.MAINCOMP_ENV) ++ comp.getDeclaredMethodsByName(AndroidConstants.COMP_ENV)
                    procedures
                }.reduce(iunion[JawaMethod])
              (InterproceduralSuperSpark(global, pros.map(_.getSignature)).icfg, outUri)
            }
            try {
              val (icfg, outUri) = Await.result(f, timer)
              val apkName = apkFileUri.substring(apkFileUri.lastIndexOf("/") + 1, apkFileUri.lastIndexOf("."))
              graphtyp match{
                case GraphType.FULL =>
                  val graph = icfg
                  val ext = format match {
                    case GraphFormat.GraphML => ".graphml"
                    case GraphFormat.GML => ".gml"
                  }
                  val file = FileUtil.toFile(outUri + "/" + apkName.filter(_.isUnicodeIdentifierPart) + ext)
                  val w = new FileOutputStream(file)
                  val zips = new BufferedOutputStream(w)
                  val zipw = new BufferedWriter(new OutputStreamWriter(zips, "UTF-8"))
                  try {
                    format match {
                      case GraphFormat.GraphML => graph.toGraphML(zipw)
                      case GraphFormat.GML => graph.toGML(zipw)
                    }
                  } catch {case e: Exception => }
                  finally {
                    zipw.close()
                  }
                case GraphType.SIMPLE_CALL =>
                  val path = new File(outputPath + "/" + apkName.filter(_.isUnicodeIdentifierPart) + "/simple_cg")
                  val fm = format match {
                    case GraphFormat.GraphML => "GraphML"
                    case GraphFormat.GML => "GML"
                  }
                  icfg.getCallGraph.toSimpleCallGraph(header, path.getPath, fm)
                case GraphType.DETAILED_CALL =>
                  val path = new File(outputPath + "/" + apkName.filter(_.isUnicodeIdentifierPart) + "/detailed_cg")
                  val fm = format match {
                    case GraphFormat.GraphML => "GraphML"
                    case GraphFormat.GML => "GML"
                  }
                  icfg.getCallGraph.toDetailedCallGraph(header, icfg, path.getPath, fm)
                case GraphType.API =>
                  val graph = icfg.toApiGraph(global)
                  val ext = format match {
                    case GraphFormat.GraphML => ".graphml"
                    case GraphFormat.GML => ".gml"
                  }
                  val file = FileUtil.toFile(outUri + "/" + apkName.filter(_.isUnicodeIdentifierPart) + ext)
                  val w = new FileOutputStream(file)
                  val zips = new BufferedOutputStream(w)
                  val zipw = new BufferedWriter(new OutputStreamWriter(zips, "UTF-8"))
                  try {
                    format match {
                      case GraphFormat.GraphML => graph.toGraphML(zipw)
                      case GraphFormat.GML => graph.toGML(zipw)
                    }
                  } catch {case e: Exception =>}
                  finally {
                    zipw.close()
                  }
              }
              println(apkName + " result stored!")
              if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
              println("Done!")
            } catch {
              case te: TimeoutException => 
                cancel()
                println(te.getMessage)
            }
         } catch {
           case e: Throwable => 
             CliLogger.logError(new File(outputPath), "Error: " , e)
         } finally {
           // before starting the analysis of the current app, first clear the previous app's records' code from the AmandroidCodeSource
           System.gc()
           System.gc()
         }
      }
    } catch {
      case e: Throwable => 
        CliLogger.logError(new File(outputPath), "Error: " , e)

    }
  }
  private def getOutputDirUri(outputUri: FileResourceUri, apkUri: FileResourceUri): FileResourceUri = {
    outputUri + {if(!outputUri.endsWith("/")) "/" else ""} + apkUri.substring(apkUri.lastIndexOf("/") + 1, apkUri.lastIndexOf("."))
  }
}
