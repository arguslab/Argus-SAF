/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import java.net.URI

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
object UriUtil {
  type UriString = String

  def lastPath(uri : UriString): String = {
    val i = uri.lastIndexOf("/")
    if (i >= i) uri.substring(i + 1)
    else uri
  }

  def normalizeUri(uri : UriString): UriString = new URI(uri).toASCIIString

  def uri(scheme : String, host : String, path : String, fragment : String) : UriString =
    new URI(scheme, host, path, fragment).toASCIIString

  def classUri(o : Any): String = o.getClass.getName.replaceAllLiterally(".", "/")
}