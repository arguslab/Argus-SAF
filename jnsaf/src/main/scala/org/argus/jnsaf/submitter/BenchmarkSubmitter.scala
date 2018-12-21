/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.submitter

import java.io.{BufferedReader, FileReader}

import org.argus.amandroid.plugin.TaintAnalysisApproach
import org.argus.jawa.core.util._

object BenchmarkSubmitter {
  private def readExpected(expectedPath: String): IMap[String, Int] = {
    val result: MMap[String, Int] = mmapEmpty
    val uri = FileUtil.toUri(expectedPath)
    val file = FileUtil.toFile(uri)
    val rdr: BufferedReader = new BufferedReader(new FileReader(file))
    var line = rdr.readLine()
    while(line != null){
      val entry = line.split("\\s+")
      result(entry(0)) = entry(1).toInt
      line = rdr.readLine()
    }
    rdr.close()
    result.toMap
  }
  def apply(sourcePath: String, address: String, port: Int, expectedFile: String, approach: TaintAnalysisApproach.Value): Unit = {
    val expected = readExpected(expectedFile)
    val analysisResult = ApkSubmitter(sourcePath, address, port, approach)
    case class Compare(var expected: Int = 0, var result: Int = 0)
    val compare: MMap[String, Compare] = mmapEmpty
    expected.foreach { case (name, num) =>
      compare(name) = Compare(expected = num)
    }
    analysisResult.foreach { case (name, res) =>
      var num = 0
      res match {
        case Some(r) =>
          num = r.paths.size
        case None =>
      }
      compare.getOrElseUpdate(name, Compare()).result = num
    }
    println("Taint analysis result:")
    println("Expected\tResult\t\tApk")
    compare.toList.sortBy(_._1).foreach { case (name, comp) =>
      println(s"${comp.expected}\t\t${comp.result}\t\t$name")
    }
  }
}
