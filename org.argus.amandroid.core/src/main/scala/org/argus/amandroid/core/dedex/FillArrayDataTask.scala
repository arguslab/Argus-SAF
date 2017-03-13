/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import java.io.IOException
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class FillArrayDataTask(target: Long, instrParser: DexInstructionToPilarParser, base: Long, offset: Long) extends PilarDedexerTask {
  var regName: String = null
  override def equals(o: PilarDedexerTask): Boolean = {
    o match {
      case fadt: FillArrayDataTask => super.equals(fadt)
      case _ => false
    }
  }

  def doTask(isSecondPass: Boolean): Unit = {
    if(!isSecondPass) {
      instrParser.placeTask(offset, this)
    }
  }
  
  def isValid: Boolean = {
    val origPos = instrParser.getFilePosition
    instrParser.setFilePosition(offset)
    val tableType = instrParser.read16Bit()
    instrParser.setFilePosition(origPos)
    if(tableType != 0x300) false
    else true
  }

  def renderTask(position: Long): IList[String] = {
    val codes: MList[String] = mlistEmpty
    val code1: StringBuilder = new StringBuilder
    code1.append("#L%06x.  ".format(instrParser.getFilePosition))
    val tableType = instrParser.read16Bit()
    if(tableType != 0x300)    // type flag for array-data
      throw new IOException("Invalid array-data table type (0x" +
                  Integer.toHexString(tableType) +
                  ") at offset 0x" +
                  java.lang.Long.toHexString(instrParser.getFilePosition - 2))
    val bytesPerElement = instrParser.read16Bit()
    val numberOfElements = instrParser.read32Bit()
    code1.append("%s:= ".format(regName))
    code1.append("(")
    for(l <- 0L to numberOfElements - 1L) {
//      val element = new StringBuilder()
//      val elementValue: Long = 0L
//      val byteOffset: Int = 0
      bytesPerElement match {
        case int if int <= 4 =>
          var v: Int = 0 
          for(i <- 0 until int) {
            v |= instrParser.read8Bit() << (i * 8)
          }
          if(l != numberOfElements - 1L) code1.append(v + ", ")
          else code1.append(v)
        case _ =>
          var v: Long = 0 
          for(i <- 0 until bytesPerElement) {
            v |= instrParser.read8Bit() << (i * 8)
          }
          if(l != numberOfElements - 1L) code1.append(v + ", ")
          else code1.append(v)
      }
    }
    code1.append(") @kind object;")
    codes += code1.toString()
    val code2: StringBuilder = new StringBuilder
    code2.append("#L%06x.  ".format(instrParser.getFilePosition - 1))
    code2.append("goto L%06x;".format(target))
    codes += code2.toString()
    codes.toList
  }

  /**
   * renderTask parses code
   */
  override def getParseFlag(position: Long): Boolean = true
}
