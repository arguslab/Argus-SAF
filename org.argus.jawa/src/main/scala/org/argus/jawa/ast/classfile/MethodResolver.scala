/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.classfile

import org.argus.jawa.ast._
import org.argus.jawa.core._
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.{Handle, Label, MethodVisitor, Opcodes}

class MethodResolver(
    api: Int,
    accessFlag: Int,
    signature: Signature,
    methods: MList[MethodDeclaration]) extends MethodVisitor(api) {
  val returnType: Type = new Type(signature.getReturnType)
  val methodSymbol: MethodDefSymbol = new MethodDefSymbol(signature.methodName)
  methodSymbol.signature = signature

  val annotations: IList[Annotation] = List(
    new Annotation("signature", SymbolValue(new SignatureSymbol(signature))(NoPosition)),
    new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
  )

  //******************************************************************************
  //                         Local Variable management
  //******************************************************************************

  val params: MList[Parameter] = mlistEmpty
  private val localVariables: MMap[Int, (JawaType, String)] = mmapEmpty
  private var num = 0

  private def load(i: Int): (JawaType, String) = {
    localVariables.getOrElse(i, throw DeBytecodeException(s"Failed to load idx $i"))
  }

  private def store(i: Int, typ: JawaType): String = {
    val name = checkAndAddVariable(typ, isTemp = false)
    localVariables(i) = ((typ, name))
    name
  }

  private val usedVariables: MMap[String, JawaType] = mmapEmpty

  private def getVarType(name: String): JawaType = usedVariables.getOrElse(name, throw DeBytecodeException(s"Variable $name does not exist."))

  // handle this
  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
    params += new Parameter(signature.getClassType, "this", List(new Annotation("kind", new TokenValue("this"))))
    localVariables(num) = ((signature.getClassType, "this"))
    usedVariables("this") = signature.getClassType
    num += 1
  }

  val locals: MList[LocalVarDeclaration] = mlistEmpty

  // handle params
  private var paramCounter = 0
  override def visitParameter(name: String, access: Int): Unit = {
    val typ: JawaType = signature.getParameterTypes.lift(paramCounter).getOrElse(throw DeBytecodeException(s"Sig: $signature does not have type for param num $paramCounter"))
    val annotations: IList[Annotation] = if(typ.isObject) {
      List(new Annotation("kind", new TokenValue("object")))
    } else {
      ilistEmpty
    }
    params += new Parameter(typ, name, annotations)
    localVariables(num) = ((typ, name))
    usedVariables(name) = typ
    paramCounter += 1
    num += 1
  }

  private def checkAndAddVariable(varType: JawaType, isTemp: Boolean): String = {
    val expectedName = if(isTemp) {
      s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
    } else {
      s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}"
    }
    var varName = expectedName
    var i = 1
    while(stackVars.contains(varName)) {
      varName = expectedName + i
      i += 1
      while({
        usedVariables.get(varName) match {
          case Some(t) => t != varType
          case None => false
        }
      }) {
        varName = expectedName + i
        i += 1
      }
    }
    if(!usedVariables.contains(varName)) {
      val lvd = new LocalVarDeclaration(varType, varName)
      locals += lvd
      usedVariables(varName) = varType
    }
    varName
  }

  private var stackVars: IList[String] = ilistEmpty

  private def push(typ: JawaType): String = {
    val varName = checkAndAddVariable(typ, isTemp = true)
    stackVars = varName :: stackVars
    varName
  }

  private def push(str: String): String = {
    stackVars = str :: stackVars
    str
  }

  private def dup(pos: Int): Unit = {
    require(stackVars.size >= pos, s"Stack size less than dup $pos requirement")
    val (front, back) = stackVars.splitAt(pos)
    stackVars = front ::: stackVars.head :: back
  }

  private def swap(): Unit = {
    require(stackVars.size >= 2, s"Stack size less than 2 for swap")
    stackVars = stackVars.take(2).reverse ::: stackVars.drop(2)
  }

  private def pop: String = {
    require(stackVars.nonEmpty, "Stack should not be empty via pop")
    val varName :: tail = stackVars
    stackVars = tail
    varName
  }

  //************************ Local Variable management End ***********************

  private var labelCount: Int = 0
  private var locCount: Int = 0
  private def line: Int = labelCount + locCount

  val locations: MList[Location] = mlistEmpty
  val catchClauses: MList[CatchClause] = mlistEmpty

  private val labels: MMap[Label, (String, EmptyStatement, IList[String])] = mmapEmpty

  private def handleLabel(label: Label): (String, EmptyStatement, IList[String]) = {
    labels.get(label) match {
      case Some(a) => a
      case None =>
        val l = s"Label$labelCount"
        val es = new EmptyStatement()
        labels(label) = ((l, es, stackVars))
        labelCount += 1
        (l, es, stackVars)
    }
  }

  private def createLocation(stmt: Statement): Unit = {
    val l = s"L$locCount"
    val loc = new Location(l, stmt)
    loc.locationSymbol.locationIndex = line
    locations += loc
    locCount += 1
  }

  override def visitLabel(label: Label): Unit = {
    val (l, es, newstack) = handleLabel(label)
    stackVars = newstack
    val loc = new Location(l, es)
    loc.locationSymbol.locationIndex = line
    locations += loc
  }

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  // -------------------------------------------------------------------------
  // Normal instructions
  // -------------------------------------------------------------------------

  val objectAnnotation = new Annotation("kind", new TokenValue("object"))

  import Opcodes._

  /**
    * Visits a zero operand instruction.
    *
    * @param opcode
    * the opcode of the instruction to be visited. This opcode is
    * either NOP, ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1,
    * ICONST_2, ICONST_3, ICONST_4, ICONST_5, LCONST_0, LCONST_1,
    * FCONST_0, FCONST_1, FCONST_2, DCONST_0, DCONST_1, IALOAD,
    * LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
    * IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE,
    * SASTORE, POP, POP2, DUP, DUP_X1, DUP_X2, DUP2, DUP2_X1,
    * DUP2_X2, SWAP, IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
    * IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV, IREM, LREM,
    * FREM, DREM, INEG, LNEG, FNEG, DNEG, ISHL, LSHL, ISHR, LSHR,
    * IUSHR, LUSHR, IAND, LAND, IOR, LOR, IXOR, LXOR, I2L, I2F, I2D,
    * L2I, L2F, L2D, F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
    * LCMP, FCMPL, FCMPG, DCMPL, DCMPG, IRETURN, LRETURN, FRETURN,
    * DRETURN, ARETURN, RETURN, ARRAYLENGTH, ATHROW, MONITORENTER,
    * or MONITOREXIT.
    */
  override def visitInsn(opcode: Int): Unit = {
    var stmt: Option[Statement] = None
    opcode match {
      case NOP =>
        stmt = Some(new EmptyStatement())
      case ACONST_NULL =>
        val name = push(JavaKnowledge.OBJECT)
        val ne = new NullExpression()
        stmt = Some(new AssignmentStatement(name, ne, ilistEmpty))
      case ICONST_M1 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, -1))
      case ICONST_0 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 0))
      case ICONST_1 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 1))
      case ICONST_2 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 2))
      case ICONST_3 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 3))
      case ICONST_4 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 4))
      case ICONST_5 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 5))
      case LCONST_0 =>
        val name = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(name, 0L))
      case LCONST_1 =>
        val name = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(name, 1L))
      case FCONST_0 =>
        val name = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(name, 0F))
      case FCONST_1 =>
        val name = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(name, 1F))
      case FCONST_2 =>
        val name = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(name, 2F))
      case DCONST_0 =>
        val name = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(name, 0D))
      case DCONST_1 =>
        val name = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(name, 1D))
      case IALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.INT)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case LALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.LONG)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case FALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.FLOAT)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case DALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.DOUBLE)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case AALOAD =>
        val idx = pop
        val base = pop
        val typ = getVarType(base)
        val tempType = JawaType.addDimensions(typ, -1)
        val temp = push(tempType)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, List(objectAnnotation)))
      case BALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.BOOLEAN)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case CALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.CHAR)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case SALOAD =>
        val idx = pop
        val base = pop
        val temp = push(JavaKnowledge.SHORT)
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case IASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case LASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case FASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case DASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case AASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, List(objectAnnotation)))
      case BASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case CASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case SASTORE =>
        val value = pop
        val idx = pop
        val base = pop
        val ie = new IndexingExpression(base, List(idx))
        stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
      case POP =>
        pop
      case POP2 =>
        pop
        pop
      case DUP =>
        dup(0)
      case DUP_X1 =>
        dup(1)
      case DUP_X2 =>
        dup(1)
      case DUP2 =>
        dup(0)
      case DUP2_X1 =>
        dup(1)
      case DUP2_X2 =>
        dup(1)
      case SWAP =>
        swap()
      case IADD =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LADD =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FADD =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DADD =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISUB =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSUB =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FSUB =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DSUB =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IMUL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LMUL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FMUL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DMUL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IDIV =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LDIV =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FDIV =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DDIV =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IREM =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LREM =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FREM =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DREM =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case INEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case LNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case FNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case DNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case ISHL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^<", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHL =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^<", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISHR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^>", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^>", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IUSHR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^>>", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LUSHR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^>>", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IAND =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^&", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LAND =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^&", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IOR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^|", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LOR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^|", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IXOR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^~", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LXOR =>
        val r = pop
        val l = pop
        val be = new BinaryExpression(l, "^~", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case I2L =>
        val v = pop
        val temp = push(JavaKnowledge.LONG)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2F =>
        val v = pop
        val temp = push(JavaKnowledge.FLOAT)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2D =>
        val v = pop
        val temp = push(JavaKnowledge.DOUBLE)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2I =>
        val v = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2F =>
        val v = pop
        val temp = push(JavaKnowledge.FLOAT)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2D =>
        val v = pop
        val temp = push(JavaKnowledge.DOUBLE)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2I =>
        val v = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2L =>
        val v = pop
        val temp = push(JavaKnowledge.LONG)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2D =>
        val v = pop
        val temp = push(JavaKnowledge.DOUBLE)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2I =>
        val v = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2L =>
        val v = pop
        val temp = push(JavaKnowledge.LONG)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2F =>
        val v = pop
        val temp = push(JavaKnowledge.FLOAT)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2B =>
        val v = pop
        val temp = push(JavaKnowledge.BYTE)
        val ce = new CastExpression(JavaKnowledge.BYTE, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2C =>
        val v = pop
        val temp = push(JavaKnowledge.CHAR)
        val ce = new CastExpression(JavaKnowledge.CHAR, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2S =>
        val v = pop
        val temp = push(JavaKnowledge.SHORT)
        val ce = new CastExpression(JavaKnowledge.SHORT, v)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case LCMP =>
        val r = pop
        val l = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CmpExpression("lcmp", l, r)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case FCMPL =>
        val r = pop
        val l = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CmpExpression("fcmpl", l, r)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case FCMPG =>
        val r = pop
        val l = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CmpExpression("fcmpg", l, r)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case DCMPL =>
        val r = pop
        val l = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CmpExpression("dcmpl", l, r)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case DCMPG =>
        val r = pop
        val l = pop
        val temp = push(JavaKnowledge.INT)
        val ce = new CmpExpression("dcmpg", l, r)
        stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case IRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case LRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case FRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case DRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case ARETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name, List(objectAnnotation)))
      case RETURN =>
        stmt = Some(new ReturnStatement())
      case ARRAYLENGTH =>
        val name = pop
        val len = new LengthExpression(name)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, len, ilistEmpty))
      case ATHROW =>
        val name = pop
        stmt = Some(new ThrowStatement(name))
      case MONITORENTER =>
        val name = pop
        stmt = Some(new MonitorStatement("monitorenter", name))
      case MONITOREXIT =>
        val name = pop
        stmt = Some(new MonitorStatement("monitorexit", name))
      case _ => throw DeBytecodeException(s"Unknown opcode for Insn: $opcode")
    }
    stmt match {
      case Some(s) => createLocation(s)
      case None =>
    }
  }

  /**
    * Visits an instruction with a single int operand.
    *
    * @param opcode
    *            the opcode of the instruction to be visited. This opcode is
    *            either BIPUSH, SIPUSH or NEWARRAY.
    * @param operand
    *            the operand of the instruction to be visited.<br>
    *            When opcode is BIPUSH, operand value should be between
    *            Byte.MIN_VALUE and Byte.MAX_VALUE.<br>
    *            When opcode is SIPUSH, operand value should be between
    *            Short.MIN_VALUE and Short.MAX_VALUE.<br>
    *            When opcode is NEWARRAY, operand value should be one of
    *            { @link Opcodes#T_BOOLEAN}, { @link Opcodes#T_CHAR},
    *                    { @link Opcodes#T_FLOAT}, { @link Opcodes#T_DOUBLE},
    *                    { @link Opcodes#T_BYTE}, { @link Opcodes#T_SHORT},
    *                    { @link Opcodes#T_INT} or { @link Opcodes#T_LONG}.
    */
  override def visitIntInsn(opcode: Int, operand: Int): Unit = {
    val stmt: Statement = opcode match {
      case BIPUSH =>
        val temp = push(JavaKnowledge.INT)
        new AssignmentStatement(temp, operand)
      case SIPUSH =>
        val temp = push(JavaKnowledge.INT)
        new AssignmentStatement(temp, operand)
      case NEWARRAY =>
        val typ = operand match {
          case T_BOOLEAN => JavaKnowledge.BOOLEAN
          case T_CHAR => JavaKnowledge.CHAR
          case T_FLOAT => JavaKnowledge.FLOAT
          case T_DOUBLE => JavaKnowledge.DOUBLE
          case T_BYTE => JavaKnowledge.BYTE
          case T_SHORT => JavaKnowledge.SHORT
          case T_INT => JavaKnowledge.INT
          case T_LONG => JavaKnowledge.LONG
          case _ =>  throw DeBytecodeException(s"Unknown operand for NEWARRAY: $operand")
        }
        val arrType = JawaType.addDimensions(typ, 1)
        val idx = pop
        val temp = push(arrType)
        val nae = new NewArrayExpression(typ, List(idx))
        new AssignmentStatement(temp, nae, ilistEmpty)
      case _ => throw DeBytecodeException(s"Unknown opcode for IntInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits a local variable instruction. A local variable instruction is an
    * instruction that loads or stores the value of a local variable.
    *
    * @param opcode
    * the opcode of the local variable instruction to be visited.
    * This opcode is either ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
    * ISTORE, LSTORE, FSTORE, DSTORE, ASTORE or RET.
    * @param v
    * the operand of the instruction to be visited. This operand is
    * the index of a local variable.
    */
  override def visitVarInsn(opcode: Int, v: Int): Unit = {
    var stmt: Option[Statement] = None
    opcode match {
      case ILOAD =>
        val (_, name) = load(v)
        val temp = push(name)
        new AssignmentStatement(temp, name, ilistEmpty)
      case LLOAD =>
        val (_, name) = load(v)
        val temp = push(name)
        new AssignmentStatement(temp, name, ilistEmpty)
      case FLOAD =>
        val (_, name) = load(v)
        push(name)
      case DLOAD =>
        val (_, name) = load(v)
        push(name)
      case ALOAD =>
        val (_, name) = load(v)
        push(name)
      case ISTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case LSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case FSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case DSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case ASTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, List(objectAnnotation)))
      //      case RET =>
      case _ => throw DeBytecodeException(s"Unknown opcode for VarInsn: $opcode")
    }
    stmt match {
      case Some(s) =>
        createLocation(s)
      case None =>
    }
  }

  /**
    * Visits a type instruction. A type instruction is an instruction that
    * takes the internal name of a class as parameter.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either NEW, ANEWARRAY, CHECKCAST or INSTANCEOF.
    * @param t
    * the operand of the instruction to be visited. This operand
    * must be the internal name of an object or array class (see
    * { @link Type#getInternalName() getInternalName}).
    */
  override def visitTypeInsn(opcode: Int, t: String): Unit = {
    val typ = JavaKnowledge.getTypeFromName(getClassName(t))
    val stmt: Statement = opcode match {
      case NEW =>
        val temp = push(typ)
        val ne = new NewExpression(typ)
        new AssignmentStatement(temp, ne, ilistEmpty)
      case ANEWARRAY =>
        val idx = pop
        val arrType = JawaType.addDimensions(typ, 1)
        val temp = push(arrType)
        val ne = new NewArrayExpression(typ, List(idx))
        new AssignmentStatement(temp, ne, ilistEmpty)
      case CHECKCAST =>
        val v = pop
        val temp = push(typ)
        val ce = new CastExpression(typ, v)
        new AssignmentStatement(temp, ce, List(objectAnnotation))
      case INSTANCEOF =>
        val v = pop
        val temp = push(JavaKnowledge.BOOLEAN)
        val ioe = new InstanceOfExpression(v, typ)
        new AssignmentStatement(temp, ioe, ilistEmpty)
      case _ => throw DeBytecodeException(s"Unknown opcode for TypeInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits a field instruction. A field instruction is an instruction that
    * loads or stores the value of a field of an object.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either GETSTATIC, PUTSTATIC, GETFIELD or PUTFIELD.
    * @param owner
    * the internal name of the field's owner class (see
    * { @link Type#getInternalName() getInternalName}).
    * @param name
    * the field's name.
    * @param desc
    * the field's descriptor (see { @link Type Type}).
    */
  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
    val fqn = FieldFQN(JavaKnowledge.getTypeFromName(getClassName(owner)), name, JavaKnowledge.formatSignatureToType(desc))
    val annotations: MList[Annotation] = mlistEmpty
    if(fqn.typ.isObject) {
      annotations += objectAnnotation
    }
    val stmt: Statement = opcode match {
      case GETSTATIC =>
        val temp = push(fqn.typ)
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTSTATIC =>
        val temp = pop
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case GETFIELD =>
        val base = pop
        val temp = push(fqn.typ)
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTFIELD =>
        val temp = pop
        val base = pop
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case _ => throw DeBytecodeException(s"Unknown opcode for FieldInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits a method instruction. A method instruction is an instruction that
    * invokes a method.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC or
    * INVOKEINTERFACE.
    * @param owner
    * the internal name of the method's owner class (see
    * { @link Type#getInternalName() getInternalName}).
    * @param name
    * the method's name.
    * @param desc
    * the method's descriptor (see { @link Type Type}).
    * @param itf
    * if the method's owner class is an interface.
    */
  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
    val typ = JavaKnowledge.getTypeFromName(getClassName(owner))
    val sig = new Signature(typ, name, desc)
    val stmt: Statement = opcode match {
      case INVOKEVIRTUAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "virtual")
      case INVOKESPECIAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "direct")
      case INVOKESTATIC =>
        val argNum = sig.getParameterNum
        val argNames = (0 until argNum).map(_ => pop).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "static")
      case INVOKEINTERFACE =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "interface")
      case _ => throw DeBytecodeException(s"Unknown opcode for MethodInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits an invokedynamic instruction.
    *
    * @param name
    * the method's name.
    * @param desc
    * the method's descriptor (see { @link Type Type}).
    * @param bsm
    * the bootstrap method.
    * @param bsmArgs
    * the bootstrap method constant arguments. Each argument must be
    * an { @link Integer}, { @link Float}, { @link Long},
    *            { @link Double}, { @link String}, { @link Type} or { @link Handle}
    *            value. This method is allowed to modify the content of the
    *            array so a caller should expect that this array may change.
    */
  override def visitInvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*): Unit = {
    //TODO
    throw DeBytecodeException(s"Unhandled InvokeDynamicInsn")
  }

  /**
    * Visits a jump instruction. A jump instruction is an instruction that may
    * jump to another instruction.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IF_ICMPEQ,
    * IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
    * IF_ACMPEQ, IF_ACMPNE, GOTO, JSR, IFNULL or IFNONNULL.
    * @param label
    * the operand of the instruction to be visited. This operand is
    * a label that designates the instruction to which the jump
    * instruction may jump.
    */
  override def visitJumpInsn(opcode: Int, label: Label): Unit = {
    val stmt: Statement = opcode match {
      case IFEQ =>
        val cond = pop
        val be = new BinaryExpression(cond, "==", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFNE =>
        val cond = pop
        val be = new BinaryExpression(cond, "!=", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFLT =>
        val cond = pop
        val be = new BinaryExpression(cond, "<", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFGE =>
        val cond = pop
        val be = new BinaryExpression(cond, ">=", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFGT =>
        val cond = pop
        val be = new BinaryExpression(cond, ">", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFLE =>
        val cond = pop
        val be = new BinaryExpression(cond, "<=", new LiteralExpression(0))
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPEQ =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "==", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPNE =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "!=", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPLT =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "<", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPGE =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, ">=", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPGT =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, ">", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ICMPLE =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "<=", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ACMPEQ =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "==", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IF_ACMPNE =>
        val right = pop
        val left = pop
        val be = new BinaryExpression(left, "!=", right)
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case GOTO =>
        val (l, _, _) = handleLabel(label)
        new GotoStatement(l)
//      case JSR =>
      case IFNULL =>
        val cond = pop
        val be = new BinaryExpression(cond, "==")
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case IFNONNULL =>
        val cond = pop
        val be = new BinaryExpression(cond, "!=")
        val (l, _, _) = handleLabel(label)
        new IfStatement(be, l)
      case _ => throw DeBytecodeException(s"Unknown opcode for JumpInsn: $opcode")
    }
    createLocation(stmt)
  }

  // -------------------------------------------------------------------------
  // Special instructions
  // -------------------------------------------------------------------------

  /**
    * Visits a LDC instruction. Note that new constant types may be added in
    * future versions of the Java Virtual Machine. To easily detect new
    * constant types, implementations of this method should check for
    * unexpected constant types, like this:
    *
    * <pre>
    * if (cst instanceof Integer) {
    * // ...
    * } else if (cst instanceof Float) {
    * // ...
    * } else if (cst instanceof Long) {
    * // ...
    * } else if (cst instanceof Double) {
    * // ...
    * } else if (cst instanceof String) {
    * // ...
    * } else if (cst instanceof Type) {
    * int sort = ((Type) cst).getSort();
    * if (sort == Type.OBJECT) {
    * // ...
    * } else if (sort == Type.ARRAY) {
    * // ...
    * } else if (sort == Type.METHOD) {
    * // ...
    * } else {
    * // throw an exception
    * }
    * } else if (cst instanceof Handle) {
    * // ...
    * } else {
    * // throw an exception
    * }
    * </pre>
    *
    * @param cst
    * the constant to be loaded on the stack. This parameter must be
    * a non null { @link Integer}, a { @link Float}, a { @link Long}, a
    *                    { @link Double}, a { @link String}, a { @link Type} of OBJECT or
    *                    ARRAY sort for <tt>.class</tt> constants, for classes whose
    *                    version is 49.0, a { @link Type} of METHOD sort or a
    *                    { @link Handle} for MethodType and MethodHandle constants, for
    *                    classes whose version is 51.0.
    */
  override def visitLdcInsn(cst: Any): Unit = {
    //TODO
    throw DeBytecodeException(s"Unhandled Ldc")
  }

  /**
    * Visits an IINC instruction.
    *
    * @param v
    * index of the local variable to be incremented.
    * @param increment
    * amount to increment the local variable by.
    */
  override def visitIincInsn(v: Int, increment: Int): Unit = {
    val (_, name) = load(v)
    val be = new BinaryExpression(name, "+", new LiteralExpression(increment))
    val stmt = new AssignmentStatement(name, be, ilistEmpty)
    createLocation(stmt)
  }

  /**
    * Visits a TABLESWITCH instruction.
    *
    * @param min
    * the minimum key value.
    * @param max
    * the maximum key value.
    * @param dflt
    * beginning of the default handler block.
    * @param labels
    * beginnings of the handler blocks. <tt>labels[i]</tt> is the
    * beginning of the handler block for the <tt>min + i</tt> key.
    */
  override def visitTableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*): Unit = {
    //TODO
    throw DeBytecodeException(s"Unhandled TableSwitch")
  }

  /**
    * Visits a LOOKUPSWITCH instruction.
    *
    * @param dflt
    * beginning of the default handler block.
    * @param keys
    * the values of the keys.
    * @param labels
    * beginnings of the handler blocks. <tt>labels[i]</tt> is the
    * beginning of the handler block for the <tt>keys[i]</tt> key.
    */
  override def visitLookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]): Unit = {
    //TODO
    throw DeBytecodeException(s"Unhandled LookupSwitch")
  }

  /**
    * Visits a MULTIANEWARRAY instruction.
    *
    * @param desc
    * an array type descriptor (see { @link Type Type}).
    * @param dims
    * number of dimensions of the array to allocate.
    */
  override def visitMultiANewArrayInsn(desc: String, dims: Int): Unit = {
    val typ = JavaKnowledge.formatSignatureToType(desc)
    val idxs = (0 until dims).map(_ => pop).reverse.toList
    val temp = push(typ)
    val arrayType = JawaType.addDimensions(typ, -1)
    val ne = new NewArrayExpression(arrayType, idxs)
    val stmt = new AssignmentStatement(temp, ne, ilistEmpty)
    createLocation(stmt)
  }

  // -------------------------------------------------------------------------
  // Exceptions table entries, debug information, max stack and max locals
  // -------------------------------------------------------------------------


  /**
    * Visits a try catch block.
    *
    * @param start
    * beginning of the exception handler's scope (inclusive).
    * @param end
    * end of the exception handler's scope (exclusive).
    * @param handler
    * beginning of the exception handler's code.
    * @param type
    * internal name of the type of exceptions handled by the
    * handler, or <tt>null</tt> to catch any exceptions (for
    * "finally" blocks).
    * @throws IllegalArgumentException
    * if one of the labels has already been visited by this visitor
    * (by the { @link #visitLabel visitLabel} method).
    */
  override def visitTryCatchBlock(start: Label, end: Label, handler: Label, `type`: String): Unit = {
    if (mv != null) mv.visitTryCatchBlock(start, end, handler, `type`)
  }

  override def visitLineNumber(line: Int, start: Label): Unit = {
    labels.get(start) match {
      case Some((_, es, _)) =>
        es.annotations += new Annotation("line", new TokenValue(s"$line"))
      case _ =>
    }
  }

  override def visitLocalVariable(
      name: String,
      desc: String,
      signature: String,
      start: Label,
      end: Label,
      index: Int): Unit = {

  }

  override def visitEnd(): Unit = {
    val body: Body = ResolvedBody(locals.toList, locations.toList, catchClauses.toList)(NoPosition)
    val md = MethodDeclaration(returnType, methodSymbol, params.toList, annotations, body)(NoPosition)
    md.getAllChildren foreach {
      case vd: VarDefSymbol => vd.owner = md
      case vs: VarSymbol => vs.owner = md
      case ld: LocationDefSymbol => ld.owner = md
      case ls: LocationSymbol => ls.owner = md
      case _ =>
    }
    methods += md
  }
}
