/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import org.argus.jawa.core.elements.JawaType


/**
 * Data class representing a layout control on the android screen
 * 
 * adapted from Steven Arzt
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
final case class LayoutControl(id: Int, viewClass: JawaType, isSensitive: Boolean = false)
