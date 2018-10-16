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

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.io.FileInputStream

/**
 * Common base class for all resource parser classes
 * 
 * adapted from Steven Arzt
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
object AndroidXMLParser {
	/**
	 * Opens the given apk file and provides the given handler with a stream for
	 * accessing the contained resource manifest files
	 * @param apk The apk file to process
	 * @param fileNameFilter If this parameter is non-null, only files with a
	 * name (excluding extension) in this set will be analyzed.
	 * @param handler The handler for processing the apk file
	 * 
	 * adapted from Steven Arzt
	 * modified by: Fengguo Wei, Sankardas Roy
	 */
	def handleAndroidXMLFiles(apk: File, fileNameFilter: Set[String],
			handler: AndroidXMLHandler): Unit = {

		try {
			var archive: ZipInputStream = null
			try {
				archive = new ZipInputStream(new FileInputStream(apk))
				var entry: ZipEntry = null
				entry = archive.getNextEntry
				while (entry != null) {
					val entryName = entry.getName
					handler.handleXMLFile(entryName, fileNameFilter, archive)
					entry = archive.getNextEntry
				}
			}
			finally {
				if (archive != null)
					archive.close()
			}
		}
		catch {
		  case e: Exception =>
				e.printStackTrace()
				throw e
		}
	}
}
