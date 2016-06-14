/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.sideEffectAnalysis

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidLibSideEffectAnalysis {
  
//	def main(args: Array[String]) {
//	  val androidLibDir = AndroidGlobalConfig.android_lib_dir
//    val smallmem = false
//	  if(androidLibDir != null){
//	    val startTime = System.currentTimeMillis()
//			JawaCodeSource.preLoad(FileUtil.toUri(androidLibDir), GlobalConfig.PILAR_FILE_EXT)
//			var intraPSEResults = 
//        if(smallmem) smallMem
//        else largeMem
//      Center.reset
//      System.gc()
//      System.gc()
//	    val interPSEResult = SideEffectAnalysis.interProceduralSideEffect(intraPSEResults)
//	    intraPSEResults = null
//	    System.gc()
//	    System.gc()
//	    val outputDir = AndroidGlobalConfig.amandroid_home + "/output"
//	  	val fileDir = new File(outputDir + "/sideEffectAnalysis")
//	  	if(!fileDir.exists()) fileDir.mkdirs()
//	  	val file = new File(fileDir + "/AndroidLibSideEffectResult.xml.zip")
//	    val w = new FileOutputStream(file)
//      val zipw = new GZIPOutputStream(new BufferedOutputStream(w))
//	    AndroidXStream.toXml(interPSEResult, zipw)
//	    zipw.close()
//	    println("Result stored!")
//	    val reader = new GZIPInputStream(new FileInputStream(file))
//	    val xmlObject = AndroidXStream.fromXml(reader).asInstanceOf[InterProceduralSideEffectAnalysisResult]
//      reader.close()
//      println("xml loaded!")
//      println(interPSEResult.equals(xmlObject))
//			val endTime = System.currentTimeMillis()
//			println("Total time: " + (endTime - startTime)/1000 + "s")
//	  } else {
//	  	System.err.println("Wrong!")
//	  }
//  }
//  
//  def largeMem: GenMap[String, IntraProceduralSideEffectResult] = {
//    var x: Float = 0
//    val recSize = JawaCodeSource.getFrameworkClassCodes.size
//    val recs =
//      JawaCodeSource.getFrameworkClassCodes.par.map{
//        case (recName, code) =>
//          this.synchronized(x += 1)
//          if(x%100==0)println((x/recSize)*100 + "%")
//          if(x == recSize) println("Class resolving Done!")
//          Center.resolveClass(recName, Center.ResolveLevel.BODY)
//      }
//    val procedures = recs.par.map(_.getMethods.filter(_.isConcrete)).reduce(iunion[JawaMethod])
//    val procSize = procedures.size
//    x = 0
//    val intraPSEResults = procedures.par.map{
//      p => 
//        this.synchronized(x += 1)
//        if(x%1000==0)println((x/procSize)*100 + "%")
//        if(x == procSize) println("Intra side effect Done!")
//        (p.getSignature, SideEffectAnalysis.intraProceduralSideEffect(p))
//    }
//    intraPSEResults.toMap
//  }
//  
//  def smallMem: GenMap[String, IntraProceduralSideEffectResult] = {
//    var x: Float = 0
//    val recSize = JawaCodeSource.getFrameworkClassCodes.size
//    val intraPSEResults =
//      JawaCodeSource.getFrameworkClassCodes.flatMap{
//        case (recName, code) =>
//          this.synchronized(x += 1)
//          if(x%1000==0){
//            println((x/recSize)*100 + "%")
//            Center.reset
//            System.gc()
//          }
//          if(x == recSize) println("Class resolving Done!")
//          val rec = Center.resolveClass(recName, Center.ResolveLevel.BODY)
//          rec.getMethods.filter(_.isConcrete).map{
//            p =>
//              (p.getSignature, SideEffectAnalysis.intraProceduralSideEffect(p))
//          }
//      }
//    intraPSEResults
//  }
}
