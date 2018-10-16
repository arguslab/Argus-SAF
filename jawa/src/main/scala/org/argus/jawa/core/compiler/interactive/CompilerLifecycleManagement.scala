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

import org.argus.jawa.core.ast.CompilationUnit
import org.argus.jawa.core.io.{AbstractFile, NoPosition, Position, SourceFile}
import org.argus.jawa.core.util._

import scala.util.control.Breaks._
import scala.annotation.elidable
import scala.collection.mutable

trait CompilerLifecycleManagement { global: Global =>
  private final val SleepTime = 10
  /** A list giving all files to be resolved in the order they should be checked.
   */
  private[interactive] var allSources: IList[SourceFile] = ilistEmpty
  
  /** A list of files that crashed the compiler. They will be ignored during background
   *  compilation until they are removed from this list.
   */
  private[interactive] var ignoredFiles: ISet[AbstractFile] = isetEmpty

  /** Flush the buffer of sources that are ignored during background compilation. */
  def clearIgnoredFiles() {
    ignoredFiles = Set()
  }

  /** Remove a crashed file from the ignore buffer. Background compilation will take it into account
   *  and errors will be reported against it. */
  def enableIgnoredFile(file: AbstractFile) {
    ignoredFiles -= file
    debugLog("Removed crashed file %s. Still in the ignored buffer: %s".format(file, ignoredFiles))
  }
  
  class ResponseMap extends mutable.HashMap[SourceFile, Set[Response[CompilationUnit]]] {
    override def default(key: SourceFile): Set[Response[CompilationUnit]] = Set()
    override def += (binding: (SourceFile, Set[Response[CompilationUnit]])): ResponseMap.this.type = {
      assert(interruptsEnabled, "delayed operation within an ask")
      super.+=(binding)
    }
  }

  /** A map that associates with each abstract file the set of responses that ware waiting
   *  (via build) for the unit associated with the abstract file to be parsed and resolved
   */
  protected val getParsedEnteredResponses = new ResponseMap

  private def cleanResponses(rmap: ResponseMap): Unit = {
    for ((source, rs) <- rmap.toList) {
      for (r <- rs) {
        if (getCompilationUnit(source.file).isEmpty)
          r raise new NoSuchUnitError(source.file)
        if (r.isComplete)
          rmap(source) -= r
      }
      if (rmap(source).isEmpty)
        rmap -= source
    }
  }

  private def cleanAllResponses() {
    cleanResponses(getParsedEnteredResponses)
  }

  private def checkNoOutstanding(rmap: ResponseMap): Unit =
    for ((_, rs) <- rmap.toList; r <- rs) {
      debugLog("ERROR: missing response, request will be discarded")
      r raise new MissingResponse
    }

  def checkNoResponsesOutstanding() {
    checkNoOutstanding(getParsedEnteredResponses)
  }
  
  /** Is a background compiler run needed?
   *  Note: outOfDate is true as long as there is a background compile scheduled or going on.
   */
  protected var outOfDate = false

  def isOutOfDate: Boolean = outOfDate

  def demandNewCompilerRun(): Unit = {
    if (outOfDate) throw new FreshRunReq // cancel background compile
    else outOfDate = true            // proceed normally and enable new background compile
  }

  protected[interactive] var minRunId = 1

  private[interactive] var interruptsEnabled = true

//  private val NoResponse: Response[_] = new Response[Any]

  /** The response that is currently pending, i.e. the compiler
   *  is working on providing an asnwer for it.
   */
//  private var pendingResponse: Response[_] = NoResponse
  
  // ----------------- Polling ---------------------------------------

  case class WorkEvent(atNode: Int, atMillis: Long)

  private var moreWorkAtNode: Int = -1
  private var nodesSeen = 0
  private var lastWasReload = false

  /** The number of pollForWorks after which the presentation compiler yields.
   *  Yielding improves responsiveness on systems with few cores because it
   *  gives the UI thread a chance to get new tasks and interrupt the presentation
   *  compiler with them.
   */
  private final val yieldPeriod = 10

  /** Called from runner thread and signalDone:
   *  Poll for interrupts and execute them immediately.
   *  Then, poll for exceptions and execute them.
   *  Then, poll for work reload/doFirst commands during background checking.
   *  @param pos   The position of the tree if polling while typechecking, NoPosition otherwise
   *
   */
  private[interactive] def pollForWork(pos: Position): Boolean = {
    val change: Boolean = false
    var loop: Boolean = true
    while (loop) {
      breakable{
        loop = false
        if (!interruptsEnabled) return change
        if (pos == NoPosition || nodesSeen % yieldPeriod == 0)
          Thread.`yield`()

        def nodeWithWork(): Option[WorkEvent] =
          if (scheduler.moreWork || pendingResponse.isCancelled) Some(WorkEvent(nodesSeen, System.currentTimeMillis))
          else None

        nodesSeen += 1
        nodeWithWork() match {
          case Some(WorkEvent(id, _)) =>
            debugLog("some work at node "+id+" current = "+nodesSeen)
            moreWorkAtNode = id
          case None =>
        }

        if (nodesSeen >= moreWorkAtNode) {

          scheduler.pollInterrupt() match {
            case Some(ir) =>
              try {
                interruptsEnabled = false
                debugLog("ask started"+timeStep)
                ir.execute()
              } finally {
                debugLog("ask finished"+timeStep)
                interruptsEnabled = true
              }
            loop = true; break
            case _ =>
          }

          if (pendingResponse.isCancelled) {
            throw CancelException
          }

          scheduler.pollThrowable() match {
            case Some(_: FreshRunReq) =>
              demandNewCompilerRun()

            case Some(ShutdownReq) =>
              scheduler.synchronized { // lock the work queue so no more items are posted while we clean it up
                val units = scheduler.dequeueAll {
                  case item: WorkItem => Some(item.raiseMissing())
                  case _ => Some(())
                }

                // don't forget to service interrupt requests
                scheduler.dequeueAllInterrupts(_.execute())

                debugLog("ShutdownReq: cleaning work queue (%d items)".format(units.size))
                checkNoResponsesOutstanding()
                scheduler = new NoWorkScheduler
                throw ShutdownReq
              }

            case Some(ex: Throwable) => throw ex
            case _ =>
          }

          lastWasReload = false

          scheduler.nextWorkItem() match {
            case Some(action) =>
              try {
                debugLog("picked up work item at "+pos+": "+action+timeStep)
                action()
                debugLog("done with work item: "+action)
              } finally {
                debugLog("quitting work item: "+action+timeStep)
              }
            case None =>
          }
        }
      }
    }
    change
  }

  protected def checkForMoreWork(pos: Position) {
    if (pollForWork(pos)) demandNewCompilerRun()
  }
  
  // ----------------- The Background Runner Thread -----------------------

  private var threadId = 0

  /** The current presentation compiler runner */
  @volatile private[interactive] var compileRunner: Thread = newRunnerThread()

  /** Check that the currently executing thread is the presentation compiler thread.
   *
   *  Compiler initialization may happen on a different thread (signalled by globalPhase being NoPhase)
   */
  @elidable(elidable.WARNING)
  def assertCorrectThread() {
    assert(initializing || onCompilerThread,
        "Race condition detected: You are running a presentation compiler method outside the PC thread." +
        " Please file a issue with the current stack trace at https://github.com/sireum/jawa/issues")
  }

  /** Create a new presentation compiler runner.
   */
  private def newRunnerThread(): Thread = {
    threadId += 1
    compileRunner = new PresentationCompilerThread(this, projectName)
    compileRunner.setDaemon(true)
    compileRunner
  }

  /** Compile all loaded source files in the order given by `allSources`.
   */
  private[interactive] final def backgroundCompile() {
    informIDE("Starting new presentation compiler type checking pass")
    reporter.reset()

    // remove any files in first that are no longer maintained by presentation compiler (i.e. closed)
    allSources = allSources filter (s => hasCompilationUnit(s.file))

    // ensure all loaded units are parsed
    for (_ <- allSources) {
      serviceParsedEntered()
    }

    // sleep window
    if (lastWasReload) {
      val limit = System.currentTimeMillis()
      while (System.currentTimeMillis() < limit) {
        Thread.sleep(SleepTime)
        checkForMoreWork(NoPosition)
      }
    }

    
    // move units removable after this run to the "to-be-removed" buffer
    toBeRemoved.addAll(toBeRemovedAfterRun)
    
    // clean out stale waiting responses
    cleanAllResponses()

    // wind down
    if (getParsedEnteredResponses.nonEmpty) {
      // need another cycle to treat those
      backgroundCompile()
    } else {
      outOfDate = false
      informIDE("Everything is now up to date")
    }
  }
  
  /** Service all pending getParsedEntered requests
   */
  private def serviceParsedEntered() {
    for ((source, rs) <- getParsedEnteredResponses; r <- rs) {
      getParsedEnteredNow(source, r)
    }
    getParsedEnteredResponses.clear()
  }

  /** Move list of files to front of allSources */
  def moveToFront(fs: List[SourceFile]) {
    allSources = fs ::: (allSources diff fs)
  }
  
  /** Start the compiler background thread and turn on thread confinement checks */
  private def finishInitialization(): Unit = {
    // this flag turns on `assertCorrectThread checks`
    initializing = false

    // Only start the thread if initialization was successful. A crash while forcing symbols (for example
    // if the Scala library is not on the classpath) can leave running threads behind. See Scala IDE #1002016
    compileRunner.start()
  }

  /** The compiler has been initialized. Constructors are evaluated in textual order,
   *  if we reached here, all super constructors and the primary constructor
   *  have been executed.
   */
  finishInitialization()

}
