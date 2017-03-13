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

import org.sireum.util._
import java.io.IOException

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class SparseSwitchTask(defaultTarget: Long, instrParser: DexInstructionToPilarParser, base: Long, offset: Long) extends PilarDedexerTask {
  var regName: String = null
  private var tableLength: Long = 0L
  private val jumpTable: MList[Long] = mlistEmpty
  val defaultLabelName: String = "L%06x".format(defaultTarget)
  val labels: MList[(String, String)] = mlistEmpty
  
  override def equals(o: PilarDedexerTask): Boolean = {
    o match {
      case pst: SparseSwitchTask => super.equals(pst)
      case _ => false
    }
  }

  def doTask(isSecondPass: Boolean): Unit = {
    if(!isSecondPass) {
      // Read the jump table
      if(jumpTable.isEmpty)
        readJumpTable()
      instrParser.placeTask(offset, this)
    }
  }

  def renderTask(position: Long): IList[String] = {
    val code: StringBuilder = new StringBuilder
    code.append("#L%06x.  ".format(instrParser.getFilePosition))
    code.append("switch %s\n".format(regName))
    labels foreach{
      case (key, target) =>
        code.append("                | %s => goto %s\n".format(key, target))
    }
    code.append("                | else => goto %s;".format(defaultLabelName))
    val endTablePosition = instrParser.getFilePosition + tableLength
    instrParser.setFilePosition(endTablePosition)
    List(code.toString())
  }
  
  def isValid: Boolean = {
    val origPos = instrParser.getFilePosition
    instrParser.setFilePosition(offset)
    val tableType = instrParser.read16Bit()
    instrParser.setFilePosition(origPos)
    if(tableType != 0x200) false
    else true
  }

  // Reads the jump table and returns the offsets (compared to the jump instruction base)
  // as array of longs
  def readJumpTable(): IList[Long] = {
    if(jumpTable.isEmpty){
      val origPos = instrParser.getFilePosition
      instrParser.setFilePosition(offset)
      val tableBasePos = instrParser.getFilePosition
      val tableType = instrParser.read16Bit()
      if(tableType != 0x200)    // type flag for sparse switch tables
        throw new IOException("Invalid sparse-switch table type (0x" +
            Integer.toHexString(tableType) + ") at offset 0x" + 
            java.lang.Long.toHexString(instrParser.getFilePosition - 2))
      val tableElements = instrParser.read16Bit()
      val switchKeys: MList[Int] = mlistEmpty
      for(i <- 0 until tableElements)
        switchKeys += instrParser.readSigned32Bit()
      for(i <- 0 until tableElements) {
        val targetOffset = instrParser.readSigned32Bit()
        val keyString: String = switchKeys(i).toString
        val targetString: String = "L%06x".format(base + (targetOffset * 2))
        labels += ((keyString, targetString))
        jumpTable += base + (targetOffset * 2)
      }
      tableLength = instrParser.getFilePosition - tableBasePos
      instrParser.setFilePosition(origPos)
    }
    jumpTable.toList
  }

  override def getParseFlag(position: Long): Boolean = position == offset
}
