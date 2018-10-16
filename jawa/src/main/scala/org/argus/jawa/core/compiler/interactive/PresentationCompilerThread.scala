/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.interactive

import org.argus.jawa.core.io.NoPosition

/** A presentation compiler thread. This is a lightweight class, delegating most
 *  of its functionality to the compiler instance.
 *
 */
final class PresentationCompilerThread(var compiler: Global, name: String = "")
  extends Thread("Jawa Presentation Compiler [" + name + "]") {

  /** The presentation compiler loop.
   */
  override def run() {
    compiler.debugLog("starting new runner thread")
    while (compiler ne null) try {
      compiler.checkNoResponsesOutstanding()
      compiler.scheduler.waitForMoreWork()
      compiler.pollForWork(NoPosition)
      while (compiler.isOutOfDate) {
        try {
          compiler.backgroundCompile()
        } catch {
          case _: FreshRunReq =>
            compiler.debugLog("fresh run req caught, starting new pass")
        }
      }
    } catch {
      case ShutdownReq =>
        compiler.debugLog("exiting presentation compiler")

        // make sure we don't keep around stale instances
        compiler = null
      case ex: Throwable =>
        ex match {
          case _: FreshRunReq =>
            compiler.debugLog("fresh run req caught outside presentation compiler loop; ignored") // This shouldn't be reported
          case _ => ex.printStackTrace(); compiler.informIDE("Fatal Error: "+ex)
        }
    }
  }
}
