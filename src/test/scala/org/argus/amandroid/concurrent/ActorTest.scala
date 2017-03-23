/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.concurrent

import org.scalatest.{FlatSpec, Matchers}
import org.sireum.util._
import akka.actor._
import akka.pattern.ask

import scala.concurrent.duration._
import com.typesafe.config.ConfigFactory
import org.argus.amandroid.concurrent.util.Recorder
import org.argus.amandroid.core.decompile.ConverterUtil
import org.argus.amandroid.plugin.TaintAnalysisModules

import scala.concurrent._
import scala.concurrent.ExecutionContext.Implicits.{global => sc}
import scala.language.postfixOps

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class ActorTest extends FlatSpec with Matchers {

  "ICC_Explicit_Src_Sink" should "successfully resolved" in {
    val res = runActor(getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath)
    assert(
      res.isDefined &&
      res.get.isInstanceOf[Success] &&
      res.get.asInstanceOf[SecurityEngineSuccResult].sr.isDefined &&
      res.get.asInstanceOf[SecurityEngineSuccResult].sr.get.isInstanceOf[TaintAnalysisResult])
  }

  private def runActor(apkFile: String): Option[SecurityEngineResult] = {
    val _system = ActorSystem("ActorTest", ConfigFactory.load)
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))
    val supervisor = _system.actorOf(Props(classOf[AmandroidSupervisorActor], Recorder(outputUri)), name = "AmandroidSupervisorActor")
    val future = supervisor.ask(AnalysisSpec(apkUri, outputUri, None, removeSupportGen = true, forceDelete = true))(2 minutes).mapTo[PointsToAnalysisResult].recover{
      case ex: Exception =>
        PointsToAnalysisFailResult(apkUri, 2, ex)
    }
    val ptr = Await.result(future, 3 minutes)
    var result: Option[SecurityEngineResult] = None
    ptr match {
      case ptar: PointsToAnalysisResult with Success =>
        val future = supervisor.ask(SecurityEngineData(ptar, TaintAnalysisSpec(TaintAnalysisModules.DATA_LEAKAGE)))(1 minutes).mapTo[SecurityEngineResult].recover {
          case ex: Exception =>
            SecurityEngineFailResult(ptar.fileUri, ex)
        }
        result = Some(Await.result(future, 2 minutes))
      case _ =>
    }
    _system.terminate()
    ConverterUtil.cleanDir(outputUri)
    result
  }
}
