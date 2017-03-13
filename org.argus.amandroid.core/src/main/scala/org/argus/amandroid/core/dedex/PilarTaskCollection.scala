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

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class PilarTaskCollection(instrParser: DexInstructionToPilarParser, initialTask: PilarDedexerTask) extends PilarDedexerTask {

  def base: Long = 0
  def offset: Long = 0
  private val taskList: MList[PilarDedexerTask] = mlistEmpty
  taskList += initialTask

  def doTask(isSecondPass: Boolean): Unit = {
    taskList.foreach(_.doTask(isSecondPass))
  }

  def renderTask(position: Long): IList[String] = {
    taskList.map(_.renderTask(position)).fold(ilistEmpty)(_ ++ _)
  }

  /**
   * This specialization returns true if the string value of any of the 
   * tasks in the collection matches the invocation parameter.
   * @param str String to match
   * @return true if the parameter string matches.
   */
  override def equals(str: String): Boolean = {
    taskList.exists { x => x.equals(str) }
  }

  def addTask(task: PilarDedexerTask): Unit = {
    // First check if this task equals to some other task already in the list.
    // We don't add if it equals
    if(taskList.exists { x => x.equals(task) }) return
    val taskPriority = task.getPriority
    var found = false
    // High-priority tasks are inserted closer to the list head
    for(i <- taskList.indices) {
      val listTaskPriority = taskList(i).getPriority
      if(taskPriority > listTaskPriority) {
        taskList.insert(i, task)
        found = true
      }
    }
    if(!found)
      taskList += task
  }

  /**
   * This implementation is not really needed, we don't add TaskCollections to
   * other TaskCollections
   */
  override def getPriority: Int = {
    var priority = MIN_PRIORITY
    for(i <- taskList.indices) {
      val taskPriority = taskList(i).getPriority
      if(taskPriority > priority)
        priority = taskPriority
    }
    priority
  }

  /**
   * If any of the task parses, we return true.
   */
  override def getParseFlag(position: Long): Boolean = {
    taskList.exists { x => x.getParseFlag(position) }
  }
}
