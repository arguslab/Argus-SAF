/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.serialization

import java.io.PrintWriter

import org.argus.jawa.core.util._
import org.argus.jawa.core.{JavaKnowledge, Signature}
import org.json4s._
import org.json4s.native.Serialization
import org.json4s.native.Serialization.write

/**
  * Created by fgwei on 6/20/17.
  */
object DataCommunicator {
  def serializeStatisticDatas(outputDir: FileResourceUri, apkID: Int, data: MMap[String, MMap[String, MMap[String, (String, String, IList[String])]]]): Unit = {
    val outStageUri = FileUtil.appendFileName(outputDir, "jsonData")
    val outStageDir = FileUtil.toFile(outStageUri)
    if (!outStageDir.exists()) outStageDir.mkdirs()
    val apkRes = FileUtil.toFile(FileUtil.appendFileName(outStageUri, "statistic" + apkID + ".json"))
    val oapk = new PrintWriter(apkRes)
    implicit val formats: Formats = Serialization.formats(NoTypeHints)
    try {
      write(data, oapk)
    } catch {
      case e: Exception =>
        apkRes.delete()
        throw e
    } finally {
      oapk.flush()
      oapk.close()
    }
  }

  def serializeParameters(sig: Signature): String = {
    val classType = sig.getClassType
    val parameterTypes: String = sig.getParameterTypes.map { typ =>
      JavaKnowledge.formatTypeToName(typ)
    }.mkString(",")
    val jniParameterTypes = classType.toString() + "," + parameterTypes
    jniParameterTypes
  }
}
