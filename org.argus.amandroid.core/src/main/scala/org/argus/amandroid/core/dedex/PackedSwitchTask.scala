/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
case class PackedSwitchTask(defaultTarget: Long, instrParser: DexInstructionToPilarParser, base: Long, offset: Long) extends PilarDedexerTask {
  var regName: String = _
  private var tableLength: Long = 0L
  private var low: Int = 0
  private val jumpTable: MList[Long] = mlistEmpty
  val defaultLabelName: String = "L%06x".format(defaultTarget)
  val labels: MList[String] = mlistEmpty
  
  override def equals(o: PilarDedexerTask): Boolean = {
    o match {
      case pst: PackedSwitchTask => super.equals(pst)
      case _ => false
    }
  }

  def doTask(isSecondPass: Boolean): Unit = {
    if(!isSecondPass) {
      // Read the jump table
      if(jumpTable.isEmpty)
        readJumpTable()
      instrParser.placeTask(offset, this)
      for(i <- jumpTable.indices) {
        val target = jumpTable(i)
        labels += "L%06x".format(target)
      }
    }
  }

  def renderTask(position: Long): IList[String] = {
    val code: StringBuilder = new StringBuilder
    code.append("#L%06x.  ".format(instrParser.getFilePosition))
    code.append("switch %s\n".format(regName))
    var i = 0
    while(i < labels.length) {
      code.append("                | %d => goto %s\n".format(low + i, labels(i)))
      i += 1
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
    if(tableType != 0x100) false
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
      if(tableType != 0x100)    // type flag for packed switch tables
        throw new IOException( "Invalid packed-switch table type (0x" +
            Integer.toHexString(tableType) + ") at offset 0x" + 
            java.lang.Long.toHexString(instrParser.getFilePosition - 2))
      val tableElements = instrParser.read16Bit()
      low = instrParser.readSigned32Bit()
      for(i <- 0 until tableElements) {
        val targetOffset = instrParser.readSigned32Bit()
        jumpTable.insert(i, base + (targetOffset * 2))
      }
      tableLength = instrParser.getFilePosition - tableBasePos
      instrParser.setFilePosition(origPos)
    }
    jumpTable.toList
  }

  override def getParseFlag(position: Long): Boolean = position == offset
}
