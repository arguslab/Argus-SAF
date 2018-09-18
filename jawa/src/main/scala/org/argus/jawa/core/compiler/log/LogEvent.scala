/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.log

sealed trait LogEvent
final class Success(val msg: String) extends LogEvent
final class Trace(val exception: Throwable) extends LogEvent
final class SetLevel(val newLevel: Level.Value) extends LogEvent
final class SetTrace(val level: Int) extends LogEvent
final class SetSuccess(val enabled: Boolean) extends LogEvent
final class ControlEvent(val event: ControlEvent.Value, val msg: String) extends LogEvent

object ControlEvent extends Enumeration
{
  val Start, Header, Finish = Value
}
