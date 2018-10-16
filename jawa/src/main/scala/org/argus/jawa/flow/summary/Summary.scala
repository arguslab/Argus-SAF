/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary

import org.argus.jawa.core.elements.Signature

trait Summary[T <: SummaryRule] {
  def sig: Signature
  def rules: Seq[T]
}

trait SummaryRule {
}