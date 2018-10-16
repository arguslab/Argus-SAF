/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import org.argus.amandroid.core.decompile.DecompileLayout
import org.argus.jawa.core.util.{FileResourceUri, ISet}
import org.json4s.{CustomSerializer, Extraction, Formats, JValue}
import org.json4s.JsonDSL._

/**
  * Created by fgwei on 5/2/17.
  */
object DecompileLayoutSerializer extends CustomSerializer[DecompileLayout](format => (
  {
    case jv: JValue =>
      implicit val formats: Formats = format
      val outputUri  = (jv \ "outputUri").extract[FileResourceUri]
      val createFolder = (jv \ "createFolder").extract[Boolean]
      val srcFolder = (jv \ "srcFolder").extract[String]
      val libFolder = (jv \ "libFolder").extract[String]
      val createSeparateFolderForDexes = (jv \ "createSeparateFolderForDexes").extract[Boolean]
      val pkg = (jv \ "pkg").extract[String]
      val outputSrcUri = (jv \ "outputSrcUri").extract[FileResourceUri]
      val sourceFolders = (jv \ "sourceFolders").extract[ISet[String]]
      val libFolders = (jv \ "libFolders").extract[ISet[String]]
      val dependencies = (jv \ "dependencies").extract[ISet[String]]
      val thirdPartyLibraries = (jv \ "thirdPartyLibraries").extract[ISet[String]]
      val layout = DecompileLayout(outputUri, createFolder, srcFolder, libFolder, createSeparateFolderForDexes)
      layout.pkg = pkg
      layout.outputSrcUri = outputSrcUri
      layout.sourceFolders = sourceFolders
      layout.libFolders = libFolders
      layout.dependencies = dependencies
      layout.thirdPartyLibraries = thirdPartyLibraries
      layout
  },
  {
    case layout: DecompileLayout =>
      implicit val formats: Formats = format
      val outputUri: FileResourceUri = layout.outputSrcUri
      val createFolder: Boolean = layout.createFolder
      val srcFolder: String = layout.srcFolder
      val libFolder: String = layout.libFolder
      val createSeparateFolderForDexes: Boolean = layout.createSeparateFolderForDexes
      val pkg: String = layout.pkg
      val outputSrcUri: FileResourceUri = layout.outputSrcUri
      val sourceFolders: ISet[String] = layout.sourceFolders
      val libFolders: ISet[String] = layout.libFolders
      val dependencies: ISet[String] = layout.dependencies
      val thirdPartyLibraries: ISet[String] = layout.thirdPartyLibraries
      ("outputUri" -> outputUri) ~
      ("createFolder" -> createFolder) ~
      ("srcFolder" -> srcFolder) ~
      ("libFolder" -> libFolder) ~
      ("createSeparateFolderForDexes" -> createSeparateFolderForDexes) ~
      ("pkg" -> pkg) ~
      ("outputSrcUri" -> outputSrcUri) ~
      ("sourceFolders" -> Extraction.decompose(sourceFolders)) ~
      ("libFolders" -> Extraction.decompose(libFolders)) ~
      ("dependencies" -> Extraction.decompose(dependencies)) ~
      ("thirdPartyLibraries" -> Extraction.decompose(thirdPartyLibraries))
  }
))