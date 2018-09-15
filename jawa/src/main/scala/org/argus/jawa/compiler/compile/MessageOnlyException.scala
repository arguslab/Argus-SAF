/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.compile

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
