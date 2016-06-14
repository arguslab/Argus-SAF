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

import org.argus.jawa.core.{JawaType, Signature}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait DexConstants {
  object InstructionType extends Enumeration {
    val
      UNKNOWN_INSTRUCTION,
      REGCONST4,
      REGSTRINGCONST,
      REGSTRINGCONST_JUMBO,
      METHODINVOKE,
      METHODINVOKE_STATIC,
      QUICKMETHODINVOKE,
      INLINEMETHODINVOKE,
      INLINEMETHODINVOKE_RANGE,
      NEWARRAY,
      FILLARRAYDATA,
      ONEREGFIELD_READ,
      ONEREGFIELD_READ_WIDE,
      ONEREGFIELD_READ_OBJECT,
      ONEREGFIELD_WRITE,
      ONEREGFIELD_WRITE_WIDE,
      ONEREGFIELD_WRITE_OBJECT,
      TWOREGSFIELD_READ,
      TWOREGSFIELD_READ_WIDE,
      TWOREGSFIELD_READ_OBJECT,
      TWOREGSFIELD_WRITE,
      TWOREGSFIELD_WRITE_WIDE,
      TWOREGSFIELD_WRITE_OBJECT,
      NOPARAMETER,
      REGCONST16,
      REGCONST16_WIDE,
      THREEREGS,
      THREEREGS_WIDE,
      ARRGET,
      ARRPUT,
      PACKEDSWITCH,
      SPARSESWITCH,
      ONEREG,
      MOVERESULT,
      OFFSET8,
      NEWINSTANCE,
      TWOREGSTYPE,
      REGOFFSET16,
      OFFSET16,
      OFFSET32,
      TWOREGSOFFSET16,
      MOVE,
      MOVE_OBJECT,
      TWOREGSPACKED_SINGLE,
      TWOREGSPACKED_DOUBLE,
      TWOREGSCONST8,
      REGCLASSCONST,
      REGCONST32,
      REGCONST32_WIDE,
      REGCONST64,
      REG8REG16,
      REG8REG16_OBJECT,
      REG16REG16,
      REG16REG16_OBJECT,
      TWOREGSPACKEDCONST16,
      METHODINVOKE_RANGE,
      METHODINVOKE_RANGE_STATIC,
      QUICKMETHODINVOKE_RANGE,
      FILLEDARRAY,
      FILLEDARRAY_RANGE,
      TWOREGSQUICKOFFSET,
      TWOREGSQUICKOFFSET_WIDE,
      TWOREGSQUICKOFFSET_OBJECT,
      TWOREGSQUICKOFFSET_WRITE,
      CHECKCAST = Value
  }

  val instructionTypes: IList[InstructionType.Value] = List(
    InstructionType.NOPARAMETER,                        // 0
    InstructionType.MOVE,                               // 1
    InstructionType.REG8REG16,                          // 2
    InstructionType.REG16REG16,                         // 3
    InstructionType.MOVE,                               // 4
    InstructionType.REG8REG16,                          // 5
    InstructionType.REG16REG16,                         // 6
    InstructionType.MOVE_OBJECT,                        // 7
    InstructionType.REG8REG16_OBJECT,                   // 8
    InstructionType.REG16REG16_OBJECT,                  // 9
    InstructionType.MOVERESULT,                         // a
    InstructionType.MOVERESULT,                         // b
    InstructionType.MOVERESULT,                         // c
    InstructionType.MOVERESULT,                         // d
    InstructionType.NOPARAMETER,                        // e
    InstructionType.ONEREG,                             // f
    InstructionType.ONEREG,                             // 10
    InstructionType.ONEREG,                             // 11
    InstructionType.REGCONST4,                          // 12
    InstructionType.REGCONST16,                         // 13
    InstructionType.REGCONST32,                         // 14
    InstructionType.REGCONST16,                         // 15
    InstructionType.REGCONST16_WIDE,                    // 16
    InstructionType.REGCONST32_WIDE,                    // 17
    InstructionType.REGCONST64,                         // 18
    InstructionType.REGCONST16_WIDE,                    // 19
    InstructionType.REGSTRINGCONST,                     // 1a
    InstructionType.REGSTRINGCONST_JUMBO,               // 1b
    InstructionType.REGCLASSCONST,                      // 1c
    InstructionType.ONEREG,                             // 1d
    InstructionType.ONEREG,                             // 1e
    InstructionType.CHECKCAST,                          // 1f
    InstructionType.TWOREGSTYPE,                        // 20
    InstructionType.TWOREGSPACKED_SINGLE,               // 21
    InstructionType.NEWINSTANCE,                        // 22
    InstructionType.NEWARRAY,                           // 23
    InstructionType.FILLEDARRAY,                        // 24
    InstructionType.FILLEDARRAY_RANGE,                  // 25
    InstructionType.FILLARRAYDATA,                      // 26
    InstructionType.ONEREG,                             // 27
    InstructionType.OFFSET8,                            // 28
    InstructionType.OFFSET16,                           // 29
    InstructionType.OFFSET32,                           // 2a
    InstructionType.PACKEDSWITCH,                       // 2b
    InstructionType.SPARSESWITCH,                       // 2c
    InstructionType.THREEREGS,                          // 2d
    InstructionType.THREEREGS,                          // 2e
    InstructionType.THREEREGS,                          // 2f
    InstructionType.THREEREGS,                          // 30
    InstructionType.THREEREGS,                          // 31
    InstructionType.TWOREGSOFFSET16,                    // 32
    InstructionType.TWOREGSOFFSET16,                    // 33
    InstructionType.TWOREGSOFFSET16,                    // 34
    InstructionType.TWOREGSOFFSET16,                    // 35
    InstructionType.TWOREGSOFFSET16,                    // 36
    InstructionType.TWOREGSOFFSET16,                    // 37
    InstructionType.REGOFFSET16,                        // 38
    InstructionType.REGOFFSET16,                        // 39
    InstructionType.REGOFFSET16,                        // 3a
    InstructionType.REGOFFSET16,                        // 3b
    InstructionType.REGOFFSET16,                        // 3c
    InstructionType.REGOFFSET16,                        // 3d
    InstructionType.UNKNOWN_INSTRUCTION,                // 3e
    InstructionType.UNKNOWN_INSTRUCTION,                // 3f
    InstructionType.UNKNOWN_INSTRUCTION,                // 40
    InstructionType.UNKNOWN_INSTRUCTION,                // 41
    InstructionType.UNKNOWN_INSTRUCTION,                // 42
    InstructionType.UNKNOWN_INSTRUCTION,                // 43
    InstructionType.ARRGET,                             // 44
    InstructionType.ARRGET,                             // 45
    InstructionType.ARRGET,                             // 46
    InstructionType.ARRGET,                             // 47
    InstructionType.ARRGET,                             // 48
    InstructionType.ARRGET,                             // 49
    InstructionType.ARRGET,                             // 4a
    InstructionType.ARRPUT,                             // 4b
    InstructionType.ARRPUT,                             // 4c
    InstructionType.ARRPUT,                             // 4d
    InstructionType.ARRPUT,                             // 4e
    InstructionType.ARRPUT,                             // 4f
    InstructionType.ARRPUT,                             // 50
    InstructionType.ARRPUT,                             // 51
    InstructionType.TWOREGSFIELD_READ,                  // 52
    InstructionType.TWOREGSFIELD_READ_WIDE,             // 53
    InstructionType.TWOREGSFIELD_READ_OBJECT,           // 54
    InstructionType.TWOREGSFIELD_READ,                  // 55
    InstructionType.TWOREGSFIELD_READ,                  // 56
    InstructionType.TWOREGSFIELD_READ,                  // 57
    InstructionType.TWOREGSFIELD_READ,                  // 58
    InstructionType.TWOREGSFIELD_WRITE,                 // 59
    InstructionType.TWOREGSFIELD_WRITE_WIDE,            // 5a
    InstructionType.TWOREGSFIELD_WRITE_OBJECT,          // 5b
    InstructionType.TWOREGSFIELD_WRITE,                 // 5c
    InstructionType.TWOREGSFIELD_WRITE,                 // 5d
    InstructionType.TWOREGSFIELD_WRITE,                 // 5e
    InstructionType.TWOREGSFIELD_WRITE,                 // 5f
    InstructionType.ONEREGFIELD_READ,                   // 60
    InstructionType.ONEREGFIELD_READ_WIDE,              // 61
    InstructionType.ONEREGFIELD_READ_OBJECT,            // 62
    InstructionType.ONEREGFIELD_READ,                   // 63
    InstructionType.ONEREGFIELD_READ,                   // 64
    InstructionType.ONEREGFIELD_READ,                   // 65
    InstructionType.ONEREGFIELD_READ,                   // 66
    InstructionType.ONEREGFIELD_WRITE,                  // 67
    InstructionType.ONEREGFIELD_WRITE_WIDE,             // 68
    InstructionType.ONEREGFIELD_WRITE_OBJECT,           // 69
    InstructionType.ONEREGFIELD_WRITE,                  // 6a
    InstructionType.ONEREGFIELD_WRITE,                  // 6b
    InstructionType.ONEREGFIELD_WRITE,                  // 6c
    InstructionType.ONEREGFIELD_WRITE,                  // 6d
    InstructionType.METHODINVOKE,                       // 6e
    InstructionType.METHODINVOKE,                       // 6f
    InstructionType.METHODINVOKE,                       // 70
    InstructionType.METHODINVOKE_STATIC,                // 71
    InstructionType.METHODINVOKE,                       // 72
    InstructionType.UNKNOWN_INSTRUCTION,                // 73
    InstructionType.METHODINVOKE_RANGE,                 // 74
    InstructionType.METHODINVOKE_RANGE,                 // 75
    InstructionType.METHODINVOKE_RANGE,                 // 76
    InstructionType.METHODINVOKE_RANGE_STATIC,          // 77
    InstructionType.METHODINVOKE_RANGE,                 // 78
    InstructionType.UNKNOWN_INSTRUCTION,                // 79
    InstructionType.UNKNOWN_INSTRUCTION,                // 7a
    InstructionType.TWOREGSPACKED_SINGLE,               // 7b
    InstructionType.TWOREGSPACKED_SINGLE,               // 7c
    InstructionType.TWOREGSPACKED_DOUBLE,               // 7d
    InstructionType.TWOREGSPACKED_DOUBLE,               // 7e
    InstructionType.TWOREGSPACKED_SINGLE,               // 7f
    InstructionType.TWOREGSPACKED_DOUBLE,               // 80
    InstructionType.TWOREGSPACKED_DOUBLE,               // 81
    InstructionType.TWOREGSPACKED_SINGLE,               // 82
    InstructionType.TWOREGSPACKED_DOUBLE,               // 83
    InstructionType.TWOREGSPACKED_SINGLE,               // 84
    InstructionType.TWOREGSPACKED_SINGLE,               // 85
    InstructionType.TWOREGSPACKED_DOUBLE,               // 86
    InstructionType.TWOREGSPACKED_SINGLE,               // 87
    InstructionType.TWOREGSPACKED_DOUBLE,               // 88
    InstructionType.TWOREGSPACKED_DOUBLE,               // 89
    InstructionType.TWOREGSPACKED_SINGLE,               // 8a
    InstructionType.TWOREGSPACKED_DOUBLE,               // 8b
    InstructionType.TWOREGSPACKED_SINGLE,               // 8c
    InstructionType.TWOREGSPACKED_SINGLE,               // 8d
    InstructionType.TWOREGSPACKED_SINGLE,               // 8e
    InstructionType.TWOREGSPACKED_SINGLE,               // 8f
    InstructionType.THREEREGS,                          // 90
    InstructionType.THREEREGS,                          // 91
    InstructionType.THREEREGS,                          // 92
    InstructionType.THREEREGS,                          // 93
    InstructionType.THREEREGS,                          // 94
    InstructionType.THREEREGS,                          // 95
    InstructionType.THREEREGS,                          // 96
    InstructionType.THREEREGS,                          // 97
    InstructionType.THREEREGS,                          // 98
    InstructionType.THREEREGS,                          // 99
    InstructionType.THREEREGS,                          // 9a
    InstructionType.THREEREGS_WIDE,                     // 9b
    InstructionType.THREEREGS_WIDE,                     // 9c
    InstructionType.THREEREGS_WIDE,                     // 9d
    InstructionType.THREEREGS_WIDE,                     // 9e
    InstructionType.THREEREGS_WIDE,                     // 9f
    InstructionType.THREEREGS_WIDE,                     // a0
    InstructionType.THREEREGS_WIDE,                     // a1
    InstructionType.THREEREGS_WIDE,                     // a2
    InstructionType.THREEREGS_WIDE,                     // a3
    InstructionType.THREEREGS_WIDE,                     // a4
    InstructionType.THREEREGS_WIDE,                     // a5
    InstructionType.THREEREGS,                          // a6
    InstructionType.THREEREGS,                          // a7
    InstructionType.THREEREGS,                          // a8
    InstructionType.THREEREGS,                          // a9
    InstructionType.THREEREGS,                          // aa
    InstructionType.THREEREGS_WIDE,                     // ab
    InstructionType.THREEREGS_WIDE,                     // ac
    InstructionType.THREEREGS_WIDE,                     // ad
    InstructionType.THREEREGS_WIDE,                     // ae
    InstructionType.THREEREGS_WIDE,                     // af
    InstructionType.TWOREGSPACKED_SINGLE,               // b0
    InstructionType.TWOREGSPACKED_SINGLE,               // b1
    InstructionType.TWOREGSPACKED_SINGLE,               // b2
    InstructionType.TWOREGSPACKED_SINGLE,               // b3
    InstructionType.TWOREGSPACKED_SINGLE,               // b4
    InstructionType.TWOREGSPACKED_SINGLE,               // b5
    InstructionType.TWOREGSPACKED_SINGLE,               // b6
    InstructionType.TWOREGSPACKED_SINGLE,               // b7
    InstructionType.TWOREGSPACKED_SINGLE,               // b8
    InstructionType.TWOREGSPACKED_SINGLE,               // b9
    InstructionType.TWOREGSPACKED_SINGLE,               // ba
    InstructionType.TWOREGSPACKED_DOUBLE,               // bb
    InstructionType.TWOREGSPACKED_DOUBLE,               // bc
    InstructionType.TWOREGSPACKED_DOUBLE,               // bd
    InstructionType.TWOREGSPACKED_DOUBLE,               // be
    InstructionType.TWOREGSPACKED_DOUBLE,               // bf
    InstructionType.TWOREGSPACKED_DOUBLE,               // c0
    InstructionType.TWOREGSPACKED_DOUBLE,               // c1
    InstructionType.TWOREGSPACKED_DOUBLE,               // c2
    InstructionType.TWOREGSPACKED_DOUBLE,               // c3
    InstructionType.TWOREGSPACKED_DOUBLE,               // c4
    InstructionType.TWOREGSPACKED_DOUBLE,               // c5
    InstructionType.TWOREGSPACKED_SINGLE,               // c6
    InstructionType.TWOREGSPACKED_SINGLE,               // c7
    InstructionType.TWOREGSPACKED_SINGLE,               // c8
    InstructionType.TWOREGSPACKED_SINGLE,               // c9
    InstructionType.TWOREGSPACKED_SINGLE,               // ca
    InstructionType.TWOREGSPACKED_DOUBLE,               // cb
    InstructionType.TWOREGSPACKED_DOUBLE,               // cc
    InstructionType.TWOREGSPACKED_DOUBLE,               // cd
    InstructionType.TWOREGSPACKED_DOUBLE,               // ce
    InstructionType.TWOREGSPACKED_DOUBLE,               // cf
    InstructionType.TWOREGSPACKEDCONST16,               // d0
    InstructionType.TWOREGSPACKEDCONST16,               // d1
    InstructionType.TWOREGSPACKEDCONST16,               // d2
    InstructionType.TWOREGSPACKEDCONST16,               // d3
    InstructionType.TWOREGSPACKEDCONST16,               // d4
    InstructionType.TWOREGSPACKEDCONST16,               // d5
    InstructionType.TWOREGSPACKEDCONST16,               // d6
    InstructionType.TWOREGSPACKEDCONST16,               // d7
    InstructionType.TWOREGSCONST8,                      // d8
    InstructionType.TWOREGSCONST8,                      // d9
    InstructionType.TWOREGSCONST8,                      // da
    InstructionType.TWOREGSCONST8,                      // db
    InstructionType.TWOREGSCONST8,                      // dc
    InstructionType.TWOREGSCONST8,                      // dd
    InstructionType.TWOREGSCONST8,                      // de
    InstructionType.TWOREGSCONST8,                      // df
    InstructionType.TWOREGSCONST8,                      // e0
    InstructionType.TWOREGSCONST8,                      // e1
    InstructionType.TWOREGSCONST8,                      // e2
    InstructionType.TWOREGSFIELD_READ,                  // e3
    InstructionType.TWOREGSFIELD_WRITE,                 // e4
    InstructionType.ONEREGFIELD_READ,                   // e5
    InstructionType.ONEREGFIELD_WRITE,                  // e6
    InstructionType.TWOREGSFIELD_READ_OBJECT,           // e7
    InstructionType.TWOREGSFIELD_READ_WIDE,             // e8
    InstructionType.TWOREGSFIELD_WRITE_WIDE,            // e9
    InstructionType.ONEREGFIELD_READ_WIDE,              // ea
    InstructionType.ONEREGFIELD_WRITE_WIDE,             // eb
    InstructionType.UNKNOWN_INSTRUCTION,                // ec
    InstructionType.UNKNOWN_INSTRUCTION,                // ed
    InstructionType.INLINEMETHODINVOKE,                 // ee
    InstructionType.INLINEMETHODINVOKE_RANGE,           // ef
    InstructionType.METHODINVOKE,                       // f0
    InstructionType.NOPARAMETER,                        // f1
    InstructionType.TWOREGSQUICKOFFSET,                 // f2
    InstructionType.TWOREGSQUICKOFFSET_WIDE,            // f3
    InstructionType.TWOREGSQUICKOFFSET_OBJECT,          // f4
    InstructionType.TWOREGSQUICKOFFSET_WRITE,           // f5
    InstructionType.TWOREGSQUICKOFFSET_WRITE,           // f6
    InstructionType.TWOREGSQUICKOFFSET_WRITE,           // f7
    InstructionType.QUICKMETHODINVOKE,                  // f8
    InstructionType.QUICKMETHODINVOKE_RANGE,            // f9
    InstructionType.QUICKMETHODINVOKE,                  // fa
    InstructionType.QUICKMETHODINVOKE_RANGE,            // fb
    InstructionType.TWOREGSFIELD_WRITE_OBJECT,          // fc
    InstructionType.ONEREGFIELD_READ_OBJECT,            // fd
    InstructionType.ONEREGFIELD_WRITE_OBJECT,           // fe
    InstructionType.UNKNOWN_INSTRUCTION                 // ff
  )

  final val NOP = 0x0
  final val MOVE = 0x1
  final val MOVE_FROM16 = 0x2
  final val MOVE_16 = 0x3
  final val MOVE_WIDE = 0x4
  final val MOVE_WIDE_FROM16 = 0x5
  final val MOVE_WIDE_16 = 0x6
  final val MOVE_OBJECT = 0x7
  final val MOVE_OBJECT_FROM16 = 0x8
  final val MOVE_OBJECT_16 = 0x9
  final val MOVE_RESULT = 0xa
  final val MOVE_RESULT_WIDE = 0xb
  final val MOVE_RESULT_OBJECT = 0xc
  final val MOVE_EXCEPTION = 0xd
  final val RETURN_VOID = 0xe
  final val RETURN = 0xf
  final val RETURN_WIDE = 0x10
  final val RETURN_OBJECT = 0x11
  final val CONST_4 = 0x12
  final val CONST_16 = 0x13
  final val CONST = 0x14
  final val CONST_HIGH16 = 0x15
  final val CONST_WIDE_16 = 0x16
  final val CONST_WIDE_32 = 0x17
  final val CONST_WIDE = 0x18
  final val CONST_WIDE_HIGH16 = 0x19
  final val CONST_STRING = 0x1a
  final val CONST_STRING_JUMBO = 0x1b
  final val CONST_CLASS = 0x1c
  final val MONITOR_ENTER = 0x1d
  final val MONITOR_EXIT = 0x1e
  final val CHECK_CAST = 0x1f
  final val INSTANCE_OF = 0x20
  final val ARRAY_LENGTH = 0x21
  final val NEW_INSTANCE = 0x22
  final val NEW_ARRAY = 0x23
  final val FILLED_NEW_ARRAY = 0x24
  final val FILLED_NEW_ARRAY_RANGE = 0x25
  final val FILL_ARRAY_DATA = 0x26
  final val THROW = 0x27
  final val GOTO = 0x28
  final val GOTO_16 = 0x29
  final val GOTO_32 = 0x2a
  final val PACKED_SWITCH = 0x2b
  final val SPARSE_SWITCH = 0x2c
  final val CMPL_FLOAT = 0x2d
  final val CMPG_FLOAT = 0x2e
  final val CMPL_DOUBLE = 0x2f
  final val CMPG_DOUBLE = 0x30
  final val CMP_LONG = 0x31
  final val IF_EQ = 0x32
  final val IF_NE = 0x33
  final val IF_LT = 0x34
  final val IF_GE = 0x35
  final val IF_GT = 0x36
  final val IF_LE = 0x37
  final val IF_EQZ = 0x38
  final val IF_NEZ = 0x39
  final val IF_LTZ = 0x3a
  final val IF_GEZ = 0x3b
  final val IF_GTZ = 0x3c
  final val IF_LEZ = 0x3d
  // unused_3E
  // unused_3F
  // unused_40
  // unused_41
  // unused_42
  // unused_43
  final val AGET = 0x44
  final val AGET_WIDE = 0x45
  final val AGET_OBJECT = 0x46
  final val AGET_BOOLEAN = 0x47
  final val AGET_BYTE = 0x48
  final val AGET_CHAR = 0x49
  final val AGET_SHORT = 0x4a
  final val APUT = 0x4b
  final val APUT_WIDE = 0x4c
  final val APUT_OBJECT = 0x4d
  final val APUT_BOOLEAN = 0x4e
  final val APUT_BYTE = 0x4f
  final val APUT_CHAR = 0x50
  final val APUT_SHORT = 0x51
  final val IGET = 0x52
  final val IGET_WIDE = 0x53
  final val IGET_OBJECT = 0x54
  final val IGET_BOOLEAN = 0x55
  final val IGET_BYTE = 0x56
  final val IGET_CHAR = 0x57
  final val IGET_SHORT = 0x58
  final val IPUT = 0x59
  final val IPUT_WIDE = 0x5a
  final val IPUT_OBJECT = 0x5b
  final val IPUT_BOOLEAN = 0x5c
  final val IPUT_BYTE = 0x5d
  final val IPUT_CHAR = 0x5e
  final val IPUT_SHORT = 0x5f
  final val SGET = 0x60
  final val SGET_WIDE = 0x61
  final val SGET_OBJECT = 0x62
  final val SGET_BOOLEAN = 0x63
  final val SGET_BYTE = 0x64
  final val SGET_CHAR = 0x65
  final val SGET_SHORT = 0x66
  final val SPUT = 0x67
  final val SPUT_WIDE = 0x68
  final val SPUT_OBJECT = 0x69
  final val SPUT_BOOLEAN = 0x6a
  final val SPUT_BYTE = 0x6b
  final val SPUT_CHAR = 0x6c
  final val SPUT_SHORT = 0x6d
  final val INVOKE_VIRTUAL = 0x6e
  final val INVOKE_SUPER = 0x6f
  final val INVOKE_DIRECT = 0x70
  final val INVOKE_STATIC = 0x71
  final val INVOKE_INTERFACE = 0x72
  // unused_73
  final val INVOKE_VIRTUAL_RANGE = 0x74
  final val INVOKE_SUPER_RANGE = 0x75
  final val INVOKE_DIRECT_RANGE = 0x76
  final val INVOKE_STATIC_RANGE = 0x77
  final val INVOKE_INTERFACE_RANGE = 0x78
  // unused_79
  // unused_7a
  final val NEG_INT = 0x7b
  final val NOT_INT = 0x7c
  final val NEG_LONG = 0x7d
  final val NOT_LONG = 0x7e
  final val NEG_FLOAT = 0x7f
  final val NEG_DOUBLE = 0x80
  final val INT_TO_LONG = 0x81
  final val INT_TO_FLOAT = 0x82
  final val INT_TO_DOUBLE = 0x83
  final val LONG_TO_INT = 0x84
  final val LONG_TO_FLOAT = 0x85
  final val LONG_TO_DOUBLE = 0x86
  final val FLOAT_TO_INT = 0x87
  final val FLOAT_TO_LONG = 0x88
  final val FLOAT_TO_DOUBLE = 0x89
  final val DOUBLE_TO_INT = 0x8a
  final val DOUBLE_TO_LONG = 0x8b
  final val DOUBLE_TO_FLOAT = 0x8c
  final val INT_TO_BYTE = 0x8d
  final val INT_TO_CHAR = 0x8e
  final val INT_TO_SHORT = 0x8f
  final val ADD_INT = 0x90
  final val SUB_INT = 0x91
  final val MUL_INT = 0x92
  final val DIV_INT = 0x93
  final val REM_INT = 0x94
  final val AND_INT = 0x95
  final val OR_INT = 0x96
  final val XOR_INT = 0x97
  final val SHL_INT = 0x98
  final val SHR_INT = 0x99
  final val USHR_INT = 0x9a
  final val ADD_LONG = 0x9b
  final val SUB_LONG = 0x9c
  final val MUL_LONG = 0x9d
  final val DIV_LONG = 0x9e
  final val REM_LONG = 0x9f
  final val AND_LONG = 0xa0
  final val OR_LONG = 0xa1
  final val XOR_LONG = 0xa2
  final val SHL_LONG = 0xa3
  final val SHR_LONG = 0xa4
  final val USHR_LONG = 0xa5
  final val ADD_FLOAT = 0xa6
  final val SUB_FLOAT = 0xa7
  final val MUL_FLOAT = 0xa8
  final val DIV_FLOAT = 0xa9
  final val REM_FLOAT = 0xaa
  final val ADD_DOUBLE = 0xab
  final val SUB_DOUBLE = 0xac
  final val MUL_DOUBLE = 0xad
  final val DIV_DOUBLE = 0xae
  final val REM_DOUBLE = 0xaf
  final val ADD_INT_2ADDR = 0xb0
  final val SUB_INT_2ADDR = 0xb1
  final val MUL_INT_2ADDR = 0xb2
  final val DIV_INT_2ADDR = 0xb3
  final val REM_INT_2ADDR = 0xb4
  final val AND_INT_2ADDR = 0xb5
  final val OR_INT_2ADDR = 0xb6
  final val XOR_INT_2ADDR = 0xb7
  final val SHL_INT_2ADDR = 0xb8
  final val SHR_INT_2ADDR = 0xb9
  final val USHR_INT_2ADDR = 0xba
  final val ADD_LONG_2ADDR = 0xbb
  final val SUB_LONG_2ADDR = 0xbc
  final val MUL_LONG_2ADDR = 0xbd
  final val DIV_LONG_2ADDR = 0xbe
  final val REM_LONG_2ADDR = 0xbf
  final val AND_LONG_2ADDR = 0xc0
  final val OR_LONG_2ADDR = 0xc1
  final val XOR_LONG_2ADDR = 0xc2
  final val SHL_LONG_2ADDR = 0xc3
  final val SHR_LONG_2ADDR = 0xc4
  final val USHR_LONG_2ADDR = 0xc5
  final val ADD_FLOAT_2ADDR = 0xc6
  final val SUB_FLOAT_2ADDR = 0xc7
  final val MUL_FLOAT_2ADDR = 0xc8
  final val DIV_FLOAT_2ADDR = 0xc9
  final val REM_FLOAT_2ADDR = 0xca
  final val ADD_DOUBLE_2ADDR = 0xcb
  final val SUB_DOUBLE_2ADDR = 0xcc
  final val MUL_DOUBLE_2ADDR = 0xcd
  final val DIV_DOUBLE_2ADDR = 0xce
  final val REM_DOUBLE_2ADDR = 0xcf
  final val ADD_INT_LIT16 = 0xd0
  final val SUB_INT_LIT16 = 0xd1
  final val MUL_INT_LIT16 = 0xd2
  final val DIV_INT_LIT16 = 0xd3
  final val REM_INT_LIT16 = 0xd4
  final val AND_INT_LIT16 = 0xd5
  final val OR_INT_LIT16 = 0xd6
  final val XOR_INT_LIT16 = 0xd7
  final val ADD_INT_LIT8 = 0xd8
  final val SUB_INT_LIT8 = 0xd9
  final val MUL_INT_LIT8 = 0xda
  final val DIV_INT_LIT8 = 0xdb
  final val REM_INT_LIT8 = 0xdc
  final val AND_INT_LIT8 = 0xdd
  final val OR_INT_LIT8 = 0xde
  final val XOR_INT_LIT8 = 0xdf
  final val SHL_INT_LIT8 = 0xe0
  final val SHR_INT_LIT8 = 0xe1
  final val USHR_INT_LIT8 = 0xe2
  final val IGET_VOLATILE = 0xe3
  final val IPUT_VOLATILE = 0xe4
  final val SGET_VOLATILE = 0xe5
  final val SPUT_VOLATILE = 0xe6
  final val IGET_OBJECT_VOLATILE = 0xe7
  final val IGET_WIDE_VOLATILE = 0xe8
  final val IPUT_WIDE_VOLATILE = 0xe9
  final val SGET_WIDE_VOLATILE = 0xea
  final val SPUT_WIDE_VOLATILE = 0xeb
  // unused_EC
  // unused_ED
  final val EXECUTE_INLINE = 0xee
  final val EXECUTE_INLINE_RANGE = 0xef
  final val INVOKE_DIRECT_EMPTY = 0xf0
  final val RETURN_VOID_BARRIER = 0xf1
  final val IGET_QUICK = 0xf2
  final val IGET_WIDE_QUICK = 0xf3
  final val IGET_OBJECT_QUICK = 0xf4
  final val IPUT_QUICK = 0xf5
  final val IPUT_WIDE_QUICK = 0xf6
  final val IPUT_OBJECT_QUICK = 0xf7
  final val INVOKE_VIRTUAL_QUICK = 0xf8
  final val INVOKE_VIRTUAL_QUICK_RANGE = 0xf9
  final val INVOKE_SUPER_QUICK = 0xfa
  final val INVOKE_SUPER_QUICK_RANGE = 0xfb
  final val IPUT_OBJECT_VOLATILE = 0xfc
  final val SGET_OBJECT_VOLATILE = 0xfd
  final val SPUT_OBJECT_VOLATILE = 0xfe
  // unused_FF
  
  def nop = "@nop" // 0x00
  def move(x: String, y: String) = "%s:= %s;".format(x, y) // 0x1, 0x2, 0x3
  def moveWide(x: String, y: String) = "%s:= %s  @kind wide;".format(x, y) // 0x4, 0x5, 0x6
  def moveObject(x: String, y: String) = "%s:= %s  @kind object;".format(x, y) // 0x7, 0x8, 0x9
  def moveResult(x: String, y: String) = "%s:= %s;".format(x, y) // 0xa
  def moveResultWide(x: String, y: String) = "%s:= %s  @kind wide;".format(x, y) // 0xb
  def moveResultObject(x: String, y: String) = "%s:= %s  @kind object;".format(x, y) // 0xc
  def moveExc(x: String, y: String) = "%s:= Exception  @kind object @type ^%s;".format(x, y) // 0xd
  def returnVoid = "return  @kind void;" // 0xe
  def `return`(x: String) = "return %s;".format(x)  // 0xf
  def returnWide(x: String) = "return %s  @kind wide;".format(x) // 0x10
  def returnObj(x: String) = "return %s  @kind object;".format(x) // 0x11
  def const(x: String, y: Int, typ: JawaType, typstr: String) = {
    typ match {
      case pt if pt.isPrimitive =>
        pt.jawaName match {
          case "int" => "%s:= %dI;".format(x, y)
          case "long" => "%s:= %dL;".format(x, y)
          case "float" => "%s:= %dF;".format(x, y)
          case "double" => "%s:= %dD;".format(x, y)
          case _ => "%s:= %dI;".format(x, y)
        }
      case ot if ot.isObject =>
        "%s:= null  @type ^%s @kind object;".format(x, typstr)
      case _ => "%s:= %dI;".format(x, y)
    }
    
  } // 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
  def constWide(x: String, y: Long, typ: JawaType) = {
    typ match {
      case pt if pt.isPrimitive =>
        pt.jawaName match {
          case "int" => "%s:= %dI;".format(x, y)
          case "long" => "%s:= %dL;".format(x, y)
          case "float" => "%s:= %dF;".format(x, y)
          case "double" => "%s:= %dD;".format(x, y)
          case _ => "%s:= %dL;".format(x, y)
        }
      case ot if ot.isObject =>
        "%s:= null  @kind object;".format(x)
      case _ => "%s:= %dL;".format(x, y)
    }
  }
//  def const16(x: Int, y: Int) = "v%d:= %dI;".format(x, y) // 0x13
//  def const(x: Int, y: Long) = "v%d:= %dI  @kind int;".format(x, y) // 0x14
//  def constHigh16(x: Int, y: Int) = "v%d:= %dI  @kind int;".format(x, y) // 0x15
//  def constWide16(x: Int, y: Int) = "v%d:= %dI  @kind int;".format(x, y) // 0x16
//  def constWide32(x: Int, y: Long) = "v%d:= %dF  @kind float;".format(x, y) // 0x17
//  def constWide(x: Int, y: Long) = "v%d:= %dL  @kind long;".format(x, y) // 0x18
//  def constWideHigh16(x: Int, y: Long) = "v%d:= %dL  @kind long;".format(x, y) // 0x19
  def constString(x: String, str: String) = "%s:= \"%s\" @kind object;".format(x, str)  // 0x1a, 0x1b
  def constMString(x: String, str: String) = "%s:= \n\"\"\"\n%s\n\"\"\" @kind object;".format(x, str)  // 0x1a, 0x1b
  def constClass(x: String, typ: String) = "%s:= constclass @type ^%s @kind object;".format(x, typ) // 0x1c
  def monitorEnter(x: String) = "@monitorenter %s".format(x) // 0x1d
  def monitorExit(x: String) = "@monitorexit %s".format(x) // 0x1e
  def checkCast(x: String, typ: String, z: String) = "%s:= (%s)%s  @kind object;".format(x, typ, z) // 0x1f
  def instanceOf(x: String, y: String, typ: String) = "%s:= instanceof @variable %s @type ^%s @kind boolean;".format(x, y, typ) // 0x20
  def arrayLen(x: String, y: String) = "%s:= length @variable %s;".format(x, y) // 0x21
  def newIns(x: String, typ: String) = "%s:= new %s;".format(x, typ) // 0x22
  def newArray(x: String, basetyp: String, y: String) = "%s:= new %s[%s];".format(x, basetyp, y) // 0x23
  def filledNewArray(retName: String, baseTyp: String, regs: IList[String]) = s"$retName:= new $baseTyp[${regs.mkString(", ")}];" // 0x24
//  def filledNewArrayRange(baseTyp: String, regbase: Int, regsize: Int) = s"temp:= new $baseTyp[${(0 to regsize - 1).map(i => "v" + (regbase + i)).mkString(", ")}];" // 0x25
  def fillArrData(target: Long) = "goto L%06x;".format(target) // 0x26
  def `throw`(x: String) = "throw %s;".format(x) // 0x27
  def goto(target: Long) = "goto L%06x;".format(target) // 0x28, 0x29, 0x2a
  def switch(target: Long) = "goto L%06x;".format(target) // 0x2b, 0x2c
  def fcmpl(x: String, y: String, z: String) = "%s:= fcmpl(%s,%s);".format(x, y, z) // 0x2d
  def fcmpg(x: String, y: String, z: String) = "%s:= fcmpg(%s,%s);".format(x, y, z) // 0x2e
  def dcmpl(x: String, y: String, z: String) = "%s:= dcmpl(%s,%s);".format(x, y, z) // 0x2f
  def dcmpg(x: String, y: String, z: String) = "%s:= dcmpg(%s,%s);".format(x, y, z) // 0x30
  def lcmp(x: String, y: String, z: String) = "%s:= lcmp(%s,%s);".format(x, y, z) // 0x31
  def ifEq(x: String, y: String, target: Long) = "if %s == %s then goto L%06x;".format(x, y, target) // 0x32
  def ifNq(x: String, y: String, target: Long) = "if %s != %s then goto L%06x;".format(x, y, target) // 0x33
  def ifLt(x: String, y: String, target: Long) = "if %s < %s then goto L%06x;".format(x, y, target) // 0x34
  def ifGe(x: String, y: String, target: Long) = "if %s >= %s then goto L%06x;".format(x, y, target) // 0x35
  def ifGt(x: String, y: String, target: Long) = "if %s > %s then goto L%06x;".format(x, y, target) // 0x36
  def ifLe(x: String, y: String, target: Long) = "if %s <= %s then goto L%06x;".format(x, y, target) // 0x37
  def ifEqz(x: String, target: Long, isObject: Boolean) = {
    if(isObject) "if %s == null then goto L%06x;".format(x, target)
    else "if %s == 0 then goto L%06x;".format(x, target)
  } // 0x38
  def ifNez(x: String, target: Long, isObject: Boolean) = {
    if(isObject) "if %s != null then goto L%06x;".format(x, target)
    else "if %s != 0 then goto L%06x;".format(x, target)
  } // 0x39
  def ifLtz(x: String, target: Long) = "if %s < 0 then goto L%06x;".format(x, target) // 0x3a
  def ifGez(x: String, target: Long) = "if %s >= 0 then goto L%06x;".format(x, target) // 0x3b
  def ifGtz(x: String, target: Long) = "if %s > 0 then goto L%06x;".format(x, target) // 0x3c
  def ifLez(x: String, target: Long) = "if %s <= 0 then goto L%06x;".format(x, target) // 0x3d
  // unused 0x3e to 0x43
  def aget(x: String, y: String, z: String) = "%s:= %s[%s];".format(x, y, z) // 0x44
  def agetWide(x: String, y: String, z: String) = "%s:= %s[%s]  @kind wide;".format(x, y, z) // 0x45
  def agetObject(x: String, y: String, z: String) = "%s:= %s[%s]  @kind object;".format(x, y, z) // 0x46
  def agetBool(x: String, y: String, z: String) = "%s:= %s[%s]  @kind boolean;".format(x, y, z) // 0x47
  def agetByte(x: String, y: String, z: String) = "%s:= %s[%s]  @kind byte;".format(x, y, z) // 0x48
  def agetChar(x: String, y: String, z: String) = "%s:= %s[%s]  @kind char;".format(x, y, z) // 0x49
  def agetShort(x: String, y: String, z: String) = "%s:= %s[%s]  @kind short;".format(x, y, z) // 0x4a
  def aput(x: String, y: String, z: String) = "%s[%s]:= %s;".format(x, y, z) // 0x4b
  def aputWide(x: String, y: String, z: String) = "%s[%s]:= %s  @kind wide;".format(x, y, z) // 0x4c
  def aputObject(x: String, y: String, z: String) = "%s[%s]:= %s  @kind object;".format(x, y, z) // 0x4d
  def aputBool(x: String, y: String, z: String) = "%s[%s]:= %s  @kind boolean;".format(x, y, z) // 0x4e
  def aputByte(x: String, y: String, z: String) = "%s[%s]:= %s  @kind byte;".format(x, y, z) // 0x4f
  def aputChar(x: String, y: String, z: String) = "%s[%s]:= %s  @kind char;".format(x, y, z) // 0x50
  def aputShort(x: String, y: String, z: String) = "%s[%s]:= %s  @kind short;".format(x, y, z) // 0x51
  def iget(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s` @type ^%s;".format(x, y, field, typ) // 0x52
  def igetWide(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind wide @type ^%s;".format(x, y, field, typ) // 0x53
  def igetObject(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind object @type ^%s;".format(x, y, field, typ) // 0x54
  def igetBool(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind boolean @type ^%s;".format(x, y, field, typ) // 0x55
  def igetByte(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind byte @type ^%s;".format(x, y, field, typ) // 0x56
  def igetChar(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind char @type ^%s;".format(x, y, field, typ) // 0x57
  def igetShort(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind short @type ^%s;".format(x, y, field, typ) // 0x58
  def iput(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @type ^%s;".format(x, field, y, typ) // 0x59
  def iputWide(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind wide @type ^%s;".format(x, field, y, typ) // 0x5a
  def iputObject(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind object @type ^%s;".format(x, field, y, typ) // 0x5b
  def iputBool(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind boolean @type ^%s;".format(x, field, y, typ) // 0x5c
  def iputByte(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind byte @type ^%s;".format(x, field, y, typ) // 0x5d
  def iputChar(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind char @type ^%s;".format(x, field, y, typ) // 0x5e
  def iputShort(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind short @type ^%s;".format(x, field, y, typ) // 0x5f
  def sget(x: String, field: String, typ: String) = "%s:= `@@%s`  @type ^%s;".format(x, field, typ) // 0x60
  def sgetWide(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind long @type ^%s;".format(x, field, typ) // 0x61
  def sgetObject(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind object @type ^%s;".format(x, field, typ) // 0x62
  def sgetBool(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind boolean @type ^%s;".format(x, field, typ) // 0x63
  def sgetByte(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind byte @type ^%s;".format(x, field, typ) // 0x64
  def sgetChar(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind char @type ^%s;".format(x, field, typ) // 0x65
  def sgetShort(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind short @type ^%s;".format(x, field, typ) // 0x66
  def sput(field: String, x: String, typ: String) = "`@@%s`:= %s  @type ^%s;".format(field, x, typ) // 0x67
  def sputWide(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind wide @type ^%s;".format(field, x, typ) // 0x68
  def sputObject(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind object @type ^%s;".format(field, x, typ) // 0x69
  def sputBool(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind boolean @type ^%s;".format(field, x, typ) // 0x6a
  def sputByte(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind byte @type ^%s;".format(field, x, typ) // 0x6b
  def sputChar(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind char @type ^%s;".format(field, x, typ) // 0x6c
  def sputShort(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind short @type ^%s;".format(field, x, typ) // 0x6d
  def invokeVirtual(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind virtual;" // 0x6e
  def invokeSuper(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind super;" // 0x6f
  def invokeDirect(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind direct;" // 0x70
  def invokeStatic(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind static;" // 0x71
  def invokeInterface(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind interface;" // 0x72
  // unused 0x73
//  def invokeVirtualRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind virtual;" // 0x74
//  def invokeSuperRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind super;" // 0x75
//  def invokeDirectRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind direct;" // 0x76
//  def invokeStaticRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind static;" // 0x77
//  def invokeInterfaceRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind interface;" // 0x78
  // unused 0x79 0x7a
  def negInt(x: String, y: String) = "%s:= -%s  @kind int;".format(x, y) // 0x7b
  def notInt(x: String, y: String) = "%s:= ~%s  @kind int;".format(x, y) // 0x7c
  def negLong(x: String, y: String) = "%s:= -%s  @kind long;".format(x, y) // 0x7d
  def notLong(x: String, y: String) = "%s:= ~%s  @kind long;".format(x, y) // 0x7e
  def negFloat(x: String, y: String) = "%s:= -%s  @kind float;".format(x, y) // 0x7f
  def negDouble(x: String, y: String) = "%s:= -%s  @kind double;".format(x, y) // 0x80
  def int2Long(x: String, y: String) = "%s:= (long)%s  @kind i2l;".format(x, y) // 0x81
  def int2Float(x: String, y: String) = "%s:= (float)%s  @kind i2f;".format(x, y) // 0x82
  def int2Double(x: String, y: String) = "%s:= (double)%s  @kind i2d;".format(x, y) // 0x83
  def long2Int(x: String, y: String)  = "%s:= (int)%s  @kind l2i;".format(x, y) // 0x84
  def long2Float(x: String, y: String) = "%s:= (float)%s  @kind l2f;".format(x, y) // 0x85
  def long2Double(x: String, y: String) = "%s:= (double)%s  @kind l2d;".format(x, y) // 0x86
  def float2Int(x: String, y: String) = "%s:= (int)%s  @kind f2i;".format(x, y) // 0x87
  def float2Long(x: String, y: String) = "%s:= (long)%s  @kind f2l;".format(x, y) // 0x88
  def float2Double(x: String, y: String) = "%s:= (double)%s  @kind f2d;".format(x, y) // 0x89
  def double2Int(x: String, y: String) = "%s:= (int)%s  @kind d2i;".format(x, y) // 0x8a
  def double2Long(x: String, y: String) = "%s:= (long)%s  @kind d2l;".format(x, y) // 0x8b
  def double2Float(x: String, y: String) = "%s:= (float)%s  @kind d2f;".format(x, y) // 0x8c
  def int2Byte(x: String, y: String)  = "%s:= (byte)%s  @kind i2b;".format(x, y) // 0x8d
  def int2Char(x: String, y: String)  = "%s:= (char)%s  @kind i2c;".format(x, y) // 0x8e
  def int2short(x: String, y: String) = "%s:= (short)%s  @kind i2s;".format(x, y) // 0x8f
  def addInt(x: String, y: String, z: String) = "%s:= %s + %s  @kind int;".format(x, y, z) // 0x90
  def subInt(x: String, y: String, z: String) = "%s:= %s - %s  @kind int;".format(x, y, z) // 0x91
  def mulInt(x: String, y: String, z: String) = "%s:= %s * %s  @kind int;".format(x, y, z) // 0x92
  def divInt(x: String, y: String, z: String) = "%s:= %s / %s  @kind int;".format(x, y, z) // 0x93
  def remInt(x: String, y: String, z: String) = "%s:= %s %% %s  @kind int;".format(x, y, z) // 0x94
  def andInt(x: String, y: String, z: String) = "%s:= %s ^& %s  @kind int;".format(x, y, z) // 0x95
  def orInt(x: String, y: String, z: String) = "%s:= %s ^| %s  @kind int;".format(x, y, z) // 0x96
  def xorInt(x: String, y: String, z: String) = "%s:= %s ^~ %s  @kind int;".format(x, y, z) // 0x97
  def shlInt(x: String, y: String, z: String) = "%s:= %s ^< %s  @kind int;".format(x, y, z) // 0x98
  def shrInt(x: String, y: String, z: String) = "%s:= %s ^> %s  @kind int;".format(x, y, z) // 0x99
  def ushrInt(x: String, y: String, z: String) = "%s:= %s ^>> %s  @kind int;".format(x, y, z) // 0x9a
  def addLong(x: String, y: String, z: String) = "%s:= %s + %s  @kind long;".format(x, y, z) // 0x9b
  def subLong(x: String, y: String, z: String) = "%s:= %s - %s  @kind long;".format(x, y, z) // 0x9c
  def mulLong(x: String, y: String, z: String) = "%s:= %s * %s  @kind long;".format(x, y, z) // 0x9d
  def divLong(x: String, y: String, z: String) = "%s:= %s / %s  @kind long;".format(x, y, z) // 0x9e
  def remLong(x: String, y: String, z: String) = "%s:= %s %% %s  @kind long;".format(x, y, z) // 0x9f
  def andLong(x: String, y: String, z: String) = "%s:= %s ^& %s  @kind long;".format(x, y, z) // 0xa0
  def orLong(x: String, y: String, z: String) = "%s:= %s ^| %s  @kind long;".format(x, y, z) // 0xa1
  def xorLong(x: String, y: String, z: String) = "%s:= %s ^~ %s  @kind long;".format(x, y, z) // 0xa2
  def shlLong(x: String, y: String, z: String) = "%s:= %s ^< %s  @kind long;".format(x, y, z) // 0xa3
  def shrLong(x: String, y: String, z: String) = "%s:= %s ^> %s  @kind long;".format(x, y, z) // 0xa4
  def ushrLong(x: String, y: String, z: String) = "%s:= %s ^>> %s  @kind long;".format(x, y, z) // 0xa5
  def addFloat(x: String, y: String, z: String) = "%s:= %s + %s  @kind float;".format(x, y, z) // 0xa6
  def subFloat(x: String, y: String, z: String) = "%s:= %s - %s  @kind float;".format(x, y, z) // 0xa7
  def mulFloat(x: String, y: String, z: String) = "%s:= %s * %s  @kind float;".format(x, y, z) // 0xa8
  def divFloat(x: String, y: String, z: String) = "%s:= %s / %s  @kind float;".format(x, y, z) // 0xa9
  def remFloat(x: String, y: String, z: String) = "%s:= %s %% %s  @kind float;".format(x, y, z) // 0xaa
  def addDouble(x: String, y: String, z: String) = "%s:= %s + %s  @kind double;".format(x, y, z) // 0xab
  def subDouble(x: String, y: String, z: String) = "%s:= %s - %s  @kind double;".format(x, y, z) // 0xac
  def mulDouble(x: String, y: String, z: String) = "%s:= %s * %s  @kind double;".format(x, y, z) // 0xad
  def divDouble(x: String, y: String, z: String) = "%s:= %s / %s  @kind double;".format(x, y, z) // 0xae
  def remDouble(x: String, y: String, z: String) = "%s:= %s %% %s  @kind double;".format(x, y, z) // 0xaf
//  def addInt2addr(x: String, y: String) = "%s:= %s + %s  @kind int;".format(x, x, y) // 0xb0
//  def subInt2addr(x: String, y: String) = "%s:= %s - %s  @kind int;".format(x, x, y) // 0xb1
//  def mulInt2addr(x: String, y: String) = "%s:= %s * %s  @kind int;".format(x, x, y) // 0xb2
//  def divInt2addr(x: String, y: String) = "%s:= %s / %s  @kind int;".format(x, x, y) // 0xb3
//  def remInt2addr(x: String, y: String) = "%s:= %s %% %s  @kind int;".format(x, x, y) // 0xb4
//  def andInt2addr(x: String, y: String) = "%s:= %s ^& %s  @kind int;".format(x, x, y) // 0xb5
//  def orInt2addr(x: String, y: String)  = "%s:= %s ^| %s  @kind int;".format(x, x, y) // 0xb6
//  def xorInt2addr(x: String, y: String) = "%s:= %s ^~ %s  @kind int;".format(x, x, y) // 0xb7
//  def shlInt2addr(x: String, y: String) = "%s:= %s ^< %s  @kind int;".format(x, x, y) // 0xb8
//  def shrInt2addr(x: String, y: String) = "%s:= %s ^> %s  @kind int;".format(x, x, y) // 0xb9
//  def ushrInt2addr(x: String, y: String) = "%s:= %s ^>> %s  @kind int;".format(x, x, y) // 0xba
//  def addLong2addr(x: String, y: String) = "%s:= %s + %s  @kind long;".format(x, x, y) // 0xbb
//  def subLong2addr(x: String, y: String) = "%s:= %s - %s  @kind long;".format(x, x, y) // 0xbc
//  def mulLong2addr(x: String, y: String) = "%s:= %s * %s  @kind long;".format(x, x, y) // 0xbd
//  def divLong2addr(x: String, y: String) = "%s:= %s / %s  @kind long;".format(x, x, y) // 0xbe
//  def remLong2addr(x: String, y: String) = "%s:= %s %% %s  @kind long;".format(x, x, y) // 0xbf
//  def andLong2addr(x: String, y: String) = "%s:= %s ^& %s  @kind long;".format(x, x, y) // 0xc0
//  def orLong2addr(x: String, y: String) = "%s:= %s ^| %s  @kind long;".format(x, x, y) // 0xc1
//  def xorLong2addr(x: String, y: String) = "%s:= %s ^~ %s  @kind long;".format(x, x, y) // 0xc2
//  def shlLong2addr(x: String, y: String) = "%s:= %s ^< %s  @kind long;".format(x, x, y) // 0xc3
//  def shrLong2addr(x: String, y: String) = "%s:= %s ^> %s  @kind long;".format(x, x, y) // 0xc4
//  def ushrLong2addr(x: String, y: String) = "%s:= %s ^>> %s  @kind long;".format(x, x, y) // 0xc5
//  def addFloat2addr(x: String, y: String) = "%s:= %s + %s  @kind float;".format(x, x, y) // 0xc6
//  def subFloat2addr(x: String, y: String) = "%s:= %s - %s  @kind float;".format(x, x, y) // 0xc7
//  def mulFloat2addr(x: String, y: String) = "%s:= %s * %s  @kind float;".format(x, x, y) // 0xc8
//  def divFloat2addr(x: String, y: String) = "%s:= %s / %s  @kind float;".format(x, x, y) // 0xc9
//  def remFloat2addr(x: String, y: String) = "%s:= %s %% %s  @kind float;".format(x, x, y) // 0xca
//  def addDouble2addr(x: String, y: String) = "%s:= %s + %s  @kind double;".format(x, x, y) // 0xcb
//  def subDouble2addr(x: String, y: String) = "%s:= %s - %s  @kind double;".format(x, x, y) // 0xcc
//  def mulDouble2addr(x: String, y: String) = "%s:= %s * %s  @kind double;".format(x, x, y) // 0xcd
//  def divDouble2addr(x: String, y: String) = "%s:= %s / %s  @kind double;".format(x, x, y) // 0xce
//  def remDouble2addr(x: String, y: String) = "%s:= %s %% %s  @kind double;".format(x, x, y) // 0xcf
  def addLit16(x: String, y: String, z: Int) = "%s:= %s + %d;".format(x, y, z) // 0xd0
  def subLit16(x: String, y: String, z: Int) = "%s:= %s - %d;".format(x, y, z) // 0xd1
  def mulLit16(x: String, y: String, z: Int) = "%s:= %s * %d;".format(x, y, z) // 0xd2
  def divLit16(x: String, y: String, z: Int) = "%s:= %s / %d;".format(x, y, z) // 0xd3
  def remLit16(x: String, y: String, z: Int) = "%s:= %s %% %d;".format(x, y, z) // 0xd4
  def andLit16(x: String, y: String, z: Int) = "%s:= %s ^& %d;".format(x, y, z) // 0xd5
  def orLit16(x: String, y: String, z: Int) = "%s:= %s ^| %d;".format(x, y, z) // 0xd6
  def xorLit16(x: String, y: String, z: Int) = "%s:= %s ^~ %d;".format(x, y, z) // 0xd7
  def addLit8(x: String, y: String, z: Int) = "%s:= %s + %d;".format(x, y, z) // 0xd8
  def subLit8(x: String, y: String, z: Int) = "%s:= %s - %d;".format(x, y, z) // 0xd9
  def mulLit8(x: String, y: String, z: Int) = "%s:= %s * %d;".format(x, y, z) // 0xda
  def divLit8(x: String, y: String, z: Int) = "%s:= %s / %d;".format(x, y, z) // 0xdb
  def remLit8(x: String, y: String, z: Int) = "%s:= %s %% %d;".format(x, y, z) // 0xdc
  def andLit8(x: String, y: String, z: Int) = "%s:= %s ^& %d;".format(x, y, z) // 0xdd
  def orLit8(x: String, y: String, z: Int) = "%s:= %s ^| %d;".format(x, y, z) // 0xde
  def xorLit8(x: String, y: String, z: Int) = "%s:= %s ^~ %d;".format(x, y, z) // 0xdf
  def shlLit8(x: String, y: String, z: Int) = "%s:= %s ^< %d;".format(x, y, z) // 0xe0
  def shrLit8(x: String, y: String, z: Int) = "%s:= %s ^> %d;".format(x, y, z) // 0xe1
  def ushrLit8(x: String, y: String, z: Int) = "%s:= %s ^>> %d;".format(x, y, z) // 0xe2
  def igetVolatile(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @type ^%s;".format(x, y, field, typ) // 0xe3
  def iputVolatile(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @type ^%s;".format(x, field, y, typ) // 0xe4
  def sgetVolatile(x: String, field: String, typ: String) = "%s:= `@@%s`  @type ^%s;".format(x, field, typ) // 0xe5
  def sputVolatile(field: String, x: String, typ: String) = "`@@%s`:= %s  @type ^%s;".format(field, x, typ) // 0xe6
  def igetObjectVolatile(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind object @type ^%s;".format(x, y, field, typ) // 0xe7
  def igetWideVolatile(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind wide @type ^%s;".format(x, y, field, typ) // 0xe8
  def iputWideVolatile(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind wide @type ^%s;".format(x, field, y, typ) // 0xe9
  def sgetWideVolatile(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind wide @type ^%s;".format(x, field, typ) // 0xea
  def sputWideVolatile(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind wide @type ^%s;".format(field, x, typ) // 0xeb
  // unused 0xec 0xed
  def executeInline(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xee
    s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind static;"
  def executeInline(args: IList[Int], inlineOffset: Int) = s"@invoke execute_inline ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @inline_offset ${"0x%x".format(inlineOffset)}" // 0xee
//  def executeInlineRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xef
//    s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind direct;"
  def executeInlineRange(argbase: Int, argsize: Int, inlineOffset: Int) = s"@invoke execute_inline_range @args ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @inline_offset ${"0x%x".format(inlineOffset)}" // 0xef
  def invokeObjectInit(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind direct;" // 0xf0
  def returnVoidBarrier = "return  @kind void;" // 0xf1
  def igetQuick(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @type ^%s;".format(x, y, field, typ) // 0xf2
  def igetQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldAccess iget_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf2
  def igetWideQuick(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind wide @type ^%s;".format(x, y, field, typ) // 0xf3
  def igetWideQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldAccess iget_wide_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf3
  def igetObjectQuick(x: String, y: String, field: String, typ: String) = "%s:= %s.`%s`  @kind object @type ^%s;".format(x, y, field, typ) // 0xf4
  def igetObjectQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldAccess iget_object_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf4
  def iputQuick(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @type ^%s;".format(x, field, y, typ) // 0xf5
  def iputQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldStore iput_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf5
  def iputWideQuick(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind wide @type ^%s;".format(x, field, y, typ) // 0xf6 
  def iputWideQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldStore iput_wide_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf6
  def iputObjectQuick(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind object @type ^%s;".format(x, field, y, typ) // 0xf7
  def iputObjectQuick(x: Int, y: Int, vtableOffset: Int) = "@fieldStore iput_object_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf7
  def invokeVirtualQuick(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xf8
    s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind virtual;"
  def invokeVirtualQuick(args: IList[Int], vtableOffset: Int) = s"@invoke virtual_quick ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xf8
//  def invokeVirtualQuickRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xf9
//    s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind virtual;"
  def invokeVirtualQuickRange(argbase: Int, argsize: Int, vtableOffset: Int) = s"@invoke virtual_quick_range ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xf9
  def invokeSuperQuick(retName: Option[String], className: String, methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xfa
    s"call ${if(retName.isDefined) retName.get + ":=  " else ""}`$className.$methodName`(${args.mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind super;"
  def invokeSuperQuick(args: IList[Int], vtableOffset: Int) = s"@invoke super_quick ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xfa
//  def invokeSuperQuickRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xfb
//    s"call temp:=  `$className.$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @classDescriptor ^$classTyp @kind super;"
  def invokeSuperQuickRange(argbase: Int, argsize: Int, vtableOffset: Int) = s"@invoke super_quick_range ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xfb
  def iputObjectVolatile(x: String, field: String, y: String, typ: String) = "%s.`%s`:= %s  @kind object @type ^%s;".format(x, field, y, typ) // 0xfc
  def sgetObjectVolatile(x: String, field: String, typ: String) = "%s:= `@@%s`  @kind object @type ^%s;".format(x, field, typ) // 0xfd
  def sputObjectVolatile(field: String, x: String, typ: String) = "`@@%s`:= %s  @kind object @type ^%s;".format(field, x, typ) // 0xfe
  //unused 0xff
  
  // Codes of instructions that terminate the call flow
  final val terminateInstructions: IList[Int] = List(0x0E, 0x0F, 0x10, 0x11, 0x27, 0xF1)
}
