/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.io

abstract class Position extends InternalPositionImpl {
  type Pos = Position
  def pos: Position = this

  protected def fail(what: String) = throw new UnsupportedOperationException(s"Position.$what on $this")

  def isDefined          = false
  def isRange            = false
  def source: SourceFile = NoSourceFile
  def start: Int         = fail("start")
  def point: Int         = fail("point")
  def end: Int           = fail("end")
  def line: Int          = fail("line")
  def column: Int        = fail("column")
}

object Position {
  val tabInc = 8

  private def validate[T <: Position](pos: T): T = {
    if (pos.isRange) {
      assert(pos.start <= pos.end, s"bad position: ${pos.show}")
    }
    pos
  }

  /** Prints the message with the given position indication. */
  def formatMessage(posIn: Position, msg: String, shortenFile: Boolean): String = {
    val pos    = if (posIn eq null) NoPosition else posIn
    val prefix = pos.source match {
      case NoSourceFile     => ""
      case s if shortenFile => s.file.name + ":"
      case s                => s.file.path + ":"
    }
    prefix + (pos showError msg)
  }
  
  def calculateLine(source: SourceFile, point: Int): Int = {
    if(source ne NoSourceFile)source.offsetToLine(point) else 0
  }

  def calculateColumn(source: SourceFile, point: Int): Int = {
    var idx = source.lineToOffset(source.offsetToLine(point))
    var col = 0
    while (idx != point) {
      col += (if (source.content(idx) == '\t') Position.tabInc - col % Position.tabInc else 1)
      idx += 1
    }
    col
  }

  def offset(source: SourceFile, point: Int): Position                   = validate(new OffsetPosition(source, point))
  def range(source: SourceFile, start: Int, length: Int): Position       = validate(new RangePosition(source, start, length))
}

class OffsetPosition(sourceIn: SourceFile, pointIn: Int) extends DefinedPosition {
  override def isRange = false
  override def source: SourceFile = sourceIn
  override def point: Int = pointIn
  override def start: Int = point
  override def end: Int = point
  override def line: Int = Position.calculateLine(sourceIn, pointIn)
  override def column: Int = Position.calculateColumn(sourceIn, pointIn)
}
class RangePosition(sourceIn: SourceFile, startIn: Int, length: Int) extends OffsetPosition(sourceIn, startIn) {
  override def isRange = true
  override def start: Int = startIn
  override def end: Int = startIn + length - 1

  override def toString: String = s"Position($sourceIn line: $line column: $column)"
}

case object NoPosition extends UndefinedPosition
case class FakePos(msg: String) extends UndefinedPosition {
  override def toString: String = msg
}


sealed abstract class DefinedPosition extends Position {
  final override def isDefined = true
  override def equals(that: Any): Boolean = that match {
    case that: DefinedPosition => source.file == that.source.file && start == that.start && point == that.point && end == that.end
    case _                     => false
  }
  override def hashCode: Int = Seq[Any](source.file, start, point, end).##
  override def toString: String =
    if (isRange) s"RangePosition($fileName, $start, $line, $column)"
    else s"source-$canonicalPath,line-$line,$pointMessage$point"
  private def pointMessage  = if (point > source.length) "out-of-bounds-" else "offset="
  private def canonicalPath = source.file.canonicalPath
  private def fileName = source.file.name
}

sealed abstract class UndefinedPosition extends Position {
  final override def isDefined = false
  override def isRange         = false
  override def source: SourceFile = NoSourceFile
  override def start: Int = fail("start")
  override def point: Int = fail("point")
  override def end: Int = fail("end")
}

private[io] trait InternalPositionImpl {
  self: Position =>

  // The methods which would be abstract in Position if it were
  // possible to change Position.
  def isDefined: Boolean
  def isRange: Boolean
  def source: SourceFile
  def start: Int
  def point: Int
  def end: Int

  /** Map this position to its position in the original source file
   *  (which may be this position unchanged.)
   */
  def finalPosition: Pos = source positionInUltimateSource this

  def isTransparent              = false
  def isOffset: Boolean = isDefined && !isRange
  def isOpaqueRange: Boolean = isRange && !isTransparent
  def pointOrElse(alt: Int): Int = if (isDefined) point else alt

  /** Copy a range position with a changed value.
   */
  def withStart(start: Int): Position          = copyRange(start = start)
  def withPoint(point: Int): Position          = if (isRange) copyRange(start = point) else Position.offset(source, point)
  def withEnd(end: Int): Position              = copyRange(end = end)
  def withSource(source: SourceFile): Position = copyRange(source = source)
  def withShift(shift: Int): Position          = Position.range(source, start + shift, end - start + 1)

  /** Convert a range position to a simple offset.
   */
  def focusStart: Position = if (this.isRange) asOffset(start) else this
  def focus: Position      = if (this.isRange) asOffset(point) else this
  def focusEnd: Position   = if (this.isRange) asOffset(end) else this

  /** If you have it in for punctuation you might not like these methods.
   *  However I think they're aptly named.
   *
   *    |   means union
   *    ^   means "the point" (look, it's a caret)
   *    |^  means union, taking the point of the rhs
   *    &#94;|  means union, taking the point of the lhs
   */
  def |(that: Position, poses: Position*): Position = poses.foldLeft(this | that)(_ | _)
  def |(that: Position): Position                   = this union that
  def ^(point: Int): Position                       = this withPoint point
  def |^(that: Position): Position                  = (this | that) ^ that.point
  def ^|(that: Position): Position                  = (this | that) ^ this.point

  def union(pos: Position): Position =
    if (!pos.isRange) this
    else if (this.isRange) copyRange(start = start min pos.start, end = end max pos.end)
    else pos

  def includes(pos: Position): Boolean         = isRange && pos.isDefined && start <= pos.start && pos.end <= end
  def properlyIncludes(pos: Position): Boolean = includes(pos) && (start < pos.start || pos.end < end)
  def precedes(pos: Position): Boolean         = bothDefined(pos) && end <= pos.start
  def properlyPrecedes(pos: Position): Boolean = bothDefined(pos) && end < pos.start
  def sameRange(pos: Position): Boolean        = bothRanges(pos) && start == pos.start && end == pos.end
  // This works because it's a range position invariant that S1 < E1 and S2 < E2.
  // So if S1 < E2 and S2 < E1, then both starts precede both ends, which is the
  // necessary condition to establish that there is overlap.
  def overlaps(pos: Position): Boolean         = bothRanges(pos) && start < pos.end && pos.start < end

  def lineContent: String = if (hasSource) source.lineToString(line - 1) else ""
  def lineCaret: String   = if (hasSource) " " * (column - 1) + "^" else ""

  def showError(msg: String): String = {
    def escaped(s: String) = {
      def u(c: Int) = f"\\u$c%04x"
      def uable(c: Int) = (c < 0x20 && c != '\t') || c == 0x7F
      if (s exists (c => uable(c))) {
        val sb = new StringBuilder
        s foreach (c => sb append (if (uable(c)) u(c) else c))
        sb.toString
      } else s
    }
    def errorAt(p: Pos) = {
      def where     = p.line
      def content   = escaped(p.lineContent)
      def indicator = p.lineCaret
      f"$where: $msg%n$content%n$indicator"
    }
    finalPosition match {
      case FakePos(fmsg) => s"$fmsg $msg"
      case NoPosition    => msg
      case pos           => errorAt(pos)
    }
  }
  def showDebug: String = toString
  def show: String =
    if (isOpaqueRange) s"[$start:$end]"
    else if (isTransparent) s"<$start:$end>"
    else if (isDefined) s"[$point]"
    else "[NoPosition]"

  private def asOffset(point: Int): Position = Position.offset(source, point)
  private def copyRange(source: SourceFile = source, start: Int = start, end: Int = end): Position =
    Position.range(source, start, end - start + 1)

  private def hasSource                      = source ne NoSourceFile
  private def bothRanges(that: Position)     = isRange && that.isRange
  private def bothDefined(that: Position)    = isDefined && that.isDefined
}
