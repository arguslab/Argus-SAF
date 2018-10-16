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

import java.io.InputStream


/**
 * Common interface for handlers working on Android xml files
 * 
 * adapted from Steven Arzt
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
trait AndroidXMLHandler {
  
  /**
	 * Called when the contents of an Android xml file shall be processed
	 * @param fileName The name of the file in the APK being processed
	 * @param fileNameFilter A list of names to be used for filtering the files
	 * in the APK that actually get processed.
	 * @param stream The stream through which the resource file can be accesses
	 */
	def handleXMLFile(fileName: String, fileNameFilter: Set[String], stream: InputStream)
}
