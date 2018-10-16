/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.log

import org.argus.jawa.core.io.Position

abstract class AbstractLogger extends Logger {
  def getLevel: Level.Value
  def setLevel(newLevel: Level.Value)
  def setTrace(flag: Int)
  def getTrace: Int
  final def traceEnabled: Boolean = getTrace >= 0
  def successEnabled: Boolean
  def setSuccessEnabled(flag: Boolean): Unit

  def atLevel(level: Level.Value): Boolean = level.id >= getLevel.id
  def control(event: ControlEvent.Value, message: => String): Unit

  def logAll(events: Seq[LogEvent]): Unit
  /** Defined in terms of other methods in Logger and should not be called from them. */
  final def log(event: LogEvent) {
    event match {
      case s: Success => debug(s.msg)
      case t: Trace => trace(t.exception)
      case setL: SetLevel => setLevel(setL.newLevel)
      case setT: SetTrace => setTrace(setT.level)
      case setS: SetSuccess => setSuccessEnabled(setS.enabled)
      case c: ControlEvent => control(c.event, c.msg)
    }
  }
}

object Logger {
  private[jawa] val Null: AbstractLogger = new AbstractLogger {
    def getLevel: Level.Value = Level.Error
    def setLevel(newLevel: Level.Value) {}
    def getTrace = 0
    def setTrace(flag: Int) {}
    def successEnabled = false
    def setSuccessEnabled(flag: Boolean) {}
    def control(event: ControlEvent.Value, message: => String) {}
    def logAll(events: Seq[LogEvent]) {}
    def trace(t: Throwable) {}
    def success(message: => String) {}
    override def debug(msg: String): Unit = {}
    override def warn(msg: String): Unit = {}
    override def info(msg: String): Unit = {}
    override def error(msg: String): Unit = {}
  }

  def problem(cat: String, pos: Position, msg: String, sev: Severity.Value): Problem =
    new Problem {
      val category: String = cat
      val position: Position = pos
      val message: String = msg
      val severity: Severity.Value = sev
    }
}

/** This is intended to be the simplest logging interface for use by code that wants to log.
* It does not include configuring the logger. */
trait Logger {
  def debug(msg: String): Unit
  def warn(msg: String): Unit
  def info(msg: String): Unit
  def error(msg: String): Unit
  def trace(t: Throwable): Unit
}

/** An enumeration defining the levels available for logging.  A level includes all of the levels
* with id larger than its own id.  For example, Warn (id=3) includes Error (id=4).*/
object Level extends Enumeration {
  val Debug: Level.Value = Value(1, "debug")
  val Info: Level.Value = Value(2, "info")
  val Warn: Level.Value = Value(3, "warn")
  val Error: Level.Value = Value(4, "error")
  /** Defines the label to use for success messages.  
  * Because the label for levels is defined in this module, the success label is also defined here. */
  val SuccessLabel = "success"

  def union(a: Value, b: Value): Value = if(a.id < b.id) a else b
  def unionAll(vs: Seq[Value]): Value = vs reduceLeft union

  /** Returns the level with the given name wrapped in Some, or None if no level exists for that name. */
  def apply(s: String): Option[Value] = values.find(s == _.toString)
  /** Same as apply, defined for use in pattern matching. */
  private[jawa] def unapply(s: String) = apply(s)
}
