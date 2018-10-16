/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

/**
 * This is copied from AXMLPrinter2.jar, because it conflict with TypedValue in apktool.jar
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object TypedValue {
  def TYPE_NULL             =0
  def TYPE_REFERENCE        =1
  def TYPE_ATTRIBUTE        =2
  def TYPE_STRING           =3
  def TYPE_FLOAT            =4
  def TYPE_DIMENSION        =5
  def TYPE_FRACTION         =6
  def TYPE_FIRST_INT        =16
  def TYPE_INT_DEC          =16
  def TYPE_INT_HEX          =17
  def TYPE_INT_BOOLEAN      =18
  def TYPE_FIRST_COLOR_INT  =28
  def TYPE_INT_COLOR_ARGB8  =28
  def TYPE_INT_COLOR_RGB8   =29
  def TYPE_INT_COLOR_ARGB4  =30
  def TYPE_INT_COLOR_RGB4   =31
  def TYPE_LAST_COLOR_INT   =31
  def TYPE_LAST_INT         =31
    
  def COMPLEX_UNIT_PX       =0
  def COMPLEX_UNIT_DIP      =1
  def COMPLEX_UNIT_SP       =2
  def COMPLEX_UNIT_PT       =3
  def COMPLEX_UNIT_IN       =4
  def COMPLEX_UNIT_MM       =5
  def COMPLEX_UNIT_SHIFT    =0
  def COMPLEX_UNIT_MASK     =15
  def COMPLEX_UNIT_FRACTION =0
  def COMPLEX_UNIT_FRACTION_PARENT=1
  def COMPLEX_RADIX_23p0    =0
  def COMPLEX_RADIX_16p7    =1
  def COMPLEX_RADIX_8p15    =2
  def COMPLEX_RADIX_0p23    =3
  def COMPLEX_RADIX_SHIFT   =4
  def COMPLEX_RADIX_MASK    =3
  def COMPLEX_MANTISSA_SHIFT  =8
  def COMPLEX_MANTISSA_MASK =0xFFFFFF
  
}
