/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.compile

final class MessageOnlyException(override val toString: String) extends RuntimeException(toString)

/** A dummy exception for the top-level exception handler to know that an exception
* has been handled, but is being passed further up to indicate general failure. */
final class AlreadyHandledException(val underlying: Throwable) extends RuntimeException

/** A marker trait for a top-level exception handler to know that this exception
* doesn't make sense to display. */
trait UnprintableException extends Throwable

/** A marker trait that refines UnprintableException to indicate to a top-level exception handler
* that the code throwing this exception has already provided feedback to the user about the error condition. */
trait FeedbackProvidedException extends UnprintableException
