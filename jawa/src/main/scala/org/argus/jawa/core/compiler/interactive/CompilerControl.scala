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

import org.argus.jawa.core.ast.{CompilationUnit, JawaAstNode, JawaSymbol}
import org.argus.jawa.core.compiler.parser.JawaParser
import org.argus.jawa.core.compiler.util._
import org.argus.jawa.core.io.{AbstractFile, Position, SourceFile}

import scala.util.{Failure, Success}


/** Interface of interactive compiler to a client such as an IDE
 *  The model the presentation compiler consists of the following parts:
 *
 *  unitOfFile: The map from sourcefiles to loaded units. A sourcefile/unit is loaded if it occurs in that map.
 *
 *  manipulated by: removeUnitOf, reloadSources.
 *
 *  A call to reloadSources will add the given sources to the loaded units, and
 *  start a new background compiler pass to compile all loaded units (with the indicated sources first).
 *  The background compiler thread can be interrupted each time an AST node is
 *  completely resolved in the following ways:

 *  1. by a new call to reloadSources. This starts a new background compiler pass.
 *  2. by a call to askScopeCompletion, askToDoFirst, askLinkPos, askLastType.
 *  3. by raising an exception in the scheduler.
 *  4. by passing a high-priority action wrapped in ask { ... }.
 *
 *  Actions under 1-2 can themselves be interrupted. 
 *  High-priority actions under 4 cannot; they always run to completion.
 *  So these high-priority actions should to be short.
 *
 *  Normally, an interrupted action continues after the interrupting action is finished.
 *  However, if the interrupting action created a new run, the interrupted
 *  action is aborted. If there's an outstanding response, it will be set to
 *  a Right value with a FreshRunReq exception.
 */
trait CompilerControl { self: Global =>

  type Response[T] = org.argus.jawa.core.compiler.interactive.Response[T]

  /** The scheduler by which client and compiler communicate
   *  Must be initialized before starting compilerRunner
   */
  @volatile protected[interactive] var scheduler = new WorkScheduler

  /** Return the compilation unit attached to a source file, or None
   *  if source is not loaded.
   */
  def getUnitOf(s: SourceFile): Option[RichCompilationUnit] = getCompilationUnit(s.file)

  /** Run operation `op` on a compilation unit associated with given `source`.
   *  If source has a loaded compilation unit, this one is passed to `op`.
   *  Otherwise a new compilation unit is created, but not added to the set of loaded units.
   */
  def onUnitOf[T](source: SourceFile)(op: RichCompilationUnit => T): T = {
    val rcu: RichCompilationUnit = getCompilationUnit(source.file) match {
      case Some(r) => r
      case None =>
        val cu = parseCompilationUnit(source).get
        RichCompilationUnit(cu)
    }
    op(rcu)
  }

  /** Removes the CompilationUnit corresponding to the given SourceFile
   *  from consideration for recompilation.
   */
  def removeUnitOf(s: SourceFile): Option[RichCompilationUnit] = { removeCompilationUnit(s.file) }

  private def postWorkItem(item: WorkItem): Unit =
    if (item.onCompilerThread) item() else scheduler.postWorkItem(item)

  /** Makes sure a set of compilation units is loaded and parsed.
   *  Returns () to syncvar `response` on completion.
   *  Afterwards a new background compiler run is started with
   *  the given sources at the head of the list of to-be-compiled sources.
   */
  def askReload(sources: List[SourceFile], response: Response[Unit]): Unit = {
    val superseeded = scheduler.dequeueAll {
      case ri: ReloadItem if ri.sources == sources => Some(ri)
      case _ => None
    }
    superseeded.foreach(_.response.set(()))
    postWorkItem(ReloadItem(sources, response))
  }

  /** Removes source files and toplevel symbols, and issues a new typer run.
   *  Returns () to syncvar `response` on completion.
   */
  def askFilesDeleted(sources: List[SourceFile], response: Response[Unit]): Unit = {
    postWorkItem(FilesDeletedItem(sources, response))
  }

  /** Sets sync var `response` to the position of the definition of the given link in
   *  the given sourcefile.
   *
   *  @param   sym      The symbol referenced by the link (might come from a classfile)
   *  @param   response A response that will be set to the following:
   *                    If `source` contains a definition that is referenced by the given link
   *                    the position of that definition, otherwise NoPosition.
   *  Note: This operation does not automatically load `source`. If `source`
   *  is unloaded, it stays that way.
   */
  def askLinkPos(sym: JawaSymbol, response: Response[Position]): Unit =
    postWorkItem(AskLinkPosItem(sym, response))

  /** Asks to do unit corresponding to given source file on present and subsequent type checking passes.
   *  If the file is in the 'crashedFiles' ignore list it is removed and typechecked normally.
   */
  def askToDoFirst(source: SourceFile): Unit =
    postWorkItem(new AskToDoFirstItem(source))

  /** Sets sync var `response` to the smallest fully attributed tree that encloses position `pos`.
   *  Note: Unlike for most other ask... operations, the source file belonging to `pos` needs not be loaded.
   */
  def askTypeAt(pos: Position, response: Response[Option[JawaSymbol]]): Unit =
    postWorkItem(AskTypeAtItem(pos, response))
    
  /** If source if not yet loaded, get an outline view with askParseEntered.
   *  If source is loaded, return it.
   *  In both cases, set response to parsed tree.
   *  @param keepSrcLoaded If set to `true`, source file will be kept as a loaded unit afterwards.
   */
  def askStructure(keepSrcLoaded: Boolean)(source: SourceFile, response: Response[CompilationUnit]): Unit = {
    getCompilationUnit(source.file) match {
      case Some(rcu) => respond(response) {rcu.cu}
      case None => askParsedEntered(source, keepSrcLoaded, response)
    }
  }
    
  /** Set sync var `response` to the parse tree of `source` with all top-level symbols entered.
   *  @param source       The source file to be analyzed
   *  @param keepLoaded   If set to `true`, source file will be kept as a loaded unit afterwards.
   *                      If keepLoaded is `false` the operation is run at low priority, only after
   *                      everything is brought up to date in a regular type checker run.
   *  @param response     The response.
   */
  def askParsedEntered(source: SourceFile, keepLoaded: Boolean, response: Response[CompilationUnit]): Unit =
    postWorkItem(AskParsedEnteredItem(source, keepLoaded, response))


  /** Cancels current compiler run and start a fresh one where everything will be re-typechecked
   *  (but not re-loaded).
   */
  def askReset(): Unit = scheduler raise new FreshRunReq

  /** Tells the compile server to shutdown, and not to restart again */
  def askShutdown(): Unit = scheduler raise ShutdownReq

  /** Returns parse tree for source `source`. No symbols are entered. Syntax errors are reported.
   *
   *  This method is thread-safe and as such can safely run outside of the presentation
   *  compiler thread.
   */
  def parseCompilationUnit(source: SourceFile): Option[CompilationUnit] = {
    JawaParser.parse[CompilationUnit](Right(source), resolveBody = true, reporter, classOf[CompilationUnit]) match {
      case Success(cu) => Some(cu)
      case Failure(_) => None
    }
  }

  /** Asks for a computation to be done quickly on the presentation compiler thread */
  def ask[A](op: () => A): A = if (self.onCompilerThread) op() else scheduler doQuickly op

  /** Asks for a computation to be done on presentation compiler thread, returning
   *  a response with the result or an exception
   */
  def askForResponse[A](op: () => A): Response[A] = {
    val r = new Response[A]
    if (self.onCompilerThread) {
      try   { r set op() }
      catch { case exc: Throwable => r raise exc }
      r
    } else {
      val ir = scheduler askDoQuickly op
      ir onComplete {
        case Left(result) => r set result
        case Right(exc)   => r raise exc
      }
      r
    }
  }

  def onCompilerThread: Boolean = Thread.currentThread == compileRunner

  // items that get sent to scheduler

  abstract class WorkItem extends (() => Unit) {
    val onCompilerThread: Boolean = self.onCompilerThread

    /** Raise a MissingReponse, if the work item carries a response. */
    def raiseMissing(): Unit
  }

  case class ReloadItem(sources: List[SourceFile], response: Response[Unit]) extends WorkItem {
    def apply(): Unit = reload(sources, response)
    override def toString: String = "reload "+sources

    def raiseMissing(): Unit =
      response raise new MissingResponse
  }

  class AskToDoFirstItem(val source: SourceFile) extends WorkItem {
    def apply(): Unit = {
      moveToFront(List(source))
      enableIgnoredFile(source.file)
    }
    override def toString: String = "dofirst "+source

    def raiseMissing(): Unit = ()
  }
  
  case class AskTypeAtItem(pos: Position, response: Response[Option[JawaSymbol]]) extends WorkItem {
    def apply(): Unit = self.getTypeAt(pos, response)
    override def toString: String = "typeat "+pos.source+" "+pos.show

    def raiseMissing(): Unit =
      response raise new MissingResponse
  }

  case class AskLinkPosItem(sym: JawaSymbol, response: Response[Position]) extends WorkItem {
    def apply(): Unit = self.getLinkPos(sym, response)
    override def toString: String = "linkpos "+sym

    def raiseMissing(): Unit =
      response raise new MissingResponse
  }

  case class AskParsedEnteredItem(source: SourceFile, keepLoaded: Boolean, response: Response[CompilationUnit]) extends WorkItem {
    def apply(): Unit = self.getParsedEntered(source, keepLoaded, response, this.onCompilerThread)
    override def toString: String = "getParsedEntered "+source+", keepLoaded = "+keepLoaded

    def raiseMissing(): Unit =
      response raise new MissingResponse
  }
  
  /** Locate smallest tree that encloses position
   *  @param pos Position must be loaded
   */
  def locateAst(pos: Position): JawaAstNode = onUnitOf(pos.source) { unit => new Locator(pos) locateIn unit.cu }
  
  case class FilesDeletedItem(sources: List[SourceFile], response: Response[Unit]) extends WorkItem {
    def apply(): Unit = filesDeleted(sources, response)
    override def toString: String = "files deleted "+sources

    def raiseMissing(): Unit =
      response raise new MissingResponse
  }

  /** A do-nothing work scheduler that responds immediately with MissingResponse.
   *
   *  Used during compiler shutdown.
   */
  class NoWorkScheduler extends WorkScheduler {

    override def postWorkItem(action: Action): Unit = synchronized {
      action match {
        case w: WorkItem => w.raiseMissing()
        case _: EmptyAction => // do nothing
        case _ => println("don't know what to do with this " + action.getClass)
      }
    }

    override def doQuickly[A](op: () => A): A = {
      throw new FailedInterrupt(new Exception("Posted a work item to a compiler that's shutting down"))
    }

    override def askDoQuickly[A](op: () => A): InterruptReq { type R = A } = {
      val ir: InterruptReq {
        type R = A
      } = new InterruptReq {
        type R = A
        val todo: () => Nothing = () => throw new MissingResponse
      }
      ir.execute()
      ir
    }

  }

}

  // ---------------- Interpreted exceptions -------------------

/** Signals a request for a fresh background compiler run.
 *  Note: The object has to stay top-level so that the PresentationCompilerThread may access it.
 */
class FreshRunReq extends ControlThrowable

/** Signals a request for a shutdown of the presentation compiler.
 *  Note: The object has to stay top-level so that the PresentationCompilerThread may access it.
 */
object ShutdownReq extends ControlThrowable

class NoSuchUnitError(file: AbstractFile) extends Exception("no unit found for file "+file)

class MissingResponse extends Exception("response missing")
