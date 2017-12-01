///*
// * Copyright (c) 2017. Fengguo Wei and others.
// * All rights reserved. This program and the accompanying materials
// * are made available under the terms of the Eclipse Public License v1.0
// * which accompanies this distribution, and is available at
// * http://www.eclipse.org/legal/epl-v10.html
// *
// * Detailed contributors are listed in the CONTRIBUTOR.md
// */
//
//package org.argus.jawa.ast.classfile
//
//import org.argus.jawa.ast._
//import org.argus.jawa.core._
//import org.argus.jawa.core.io.NoPosition
//import org.argus.jawa.core.util._
//import org.objectweb.asm.{Handle, Label, MethodVisitor, Opcodes}
//
//class MethodDeclResolver(
//    api: Int,
//    accessFlag: Int,
//    signature: Signature,
//    methods: MList[MethodDeclaration]) extends MethodVisitor(api) {
//  val returnType: Type = new Type(signature.getReturnType)
//  val methodSymbol: MethodDefSymbol = new MethodDefSymbol(signature.methodName)
//  methodSymbol.signature = signature
//
//  val annotations: IList[Annotation] = List(
//    new Annotation("signature", SymbolValue(new SignatureSymbol(signature))(NoPosition)),
//    new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
//  )
//
//  private def getClassName(name: String): String = {
//    name.replaceAll("/", ".")
//  }
//
//  // -------------------------------------------------------------------------
//  // Label
//  // -------------------------------------------------------------------------
//  private var labelCount: Int = 0
//
//  private val labels: MMap[Label, (String, MList[Annotation])] = mmapEmpty
//
//  private def handleLabel(label: Label): (String, MList[Annotation]) = {
//    labels.get(label) match {
//      case Some(a) => a
//      case None =>
//        val l = s"Label$labelCount"
//        val annos: MList[Annotation] = mlistEmpty
//        labels(label) = ((l, annos))
//        labelCount += 1
//        (l, annos)
//    }
//  }
//
//  private val labelIdxs: MMap[Label, Int] = mmapEmpty
//
//  var labelIdx: Int = 0
//  var currentLabel: Label = _
//  override def visitLabel(label: Label): Unit = {
//    currentLabel = label
//    insns += LabelInsn(label)
//    labelIdxs(label) = labelIdx
//    labelIdx += 1
//  }
//
//  override def visitLineNumber(line: Int, start: Label): Unit = {
//    labels.get(start) match {
//      case Some((_, annos)) =>
//        annos += new Annotation("line", new TokenValue(s"$line"))
//      case _ =>
//    }
//  }
//
//  // -------------------------------------------------------------------------
//  // Variable management
//  // -------------------------------------------------------------------------
//
//  private val params: MList[Parameter] = mlistEmpty
//
//  private val parameterIdx: MMap[Int, (Boolean, JawaType)] = mmapEmpty
//  private var num: Int = 0
//  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
//    parameterIdx(num) = ((true, signature.getClassType))
//    num += 1
//  }
//  signature.getParameterTypes.foreach { typ =>
//    parameterIdx(num) = ((false, typ))
//    if(typ.isDWordPrimitive) {
//      num += 2
//    } else {
//      num += 1
//    }
//  }
//
//  case class VarScope(start: Label, end: Label, typ: JawaType, name: String) {
//    val min: Int = labelIdxs.getOrElse(start, 0)
//    val max: Int = labelIdxs.getOrElse(end, Integer.MAX_VALUE)
//    def inScope(l: Label): Boolean = {
//      val idx = labelIdxs.getOrElse(l, 0)
//      min <= idx && idx < max
//    }
//  }
//
//  private val localVariables: MMap[Int, MSet[VarScope]] = mmapEmpty
//
//  /**
//    * Visits a local variable declaration.
//    *
//    * @param name
//    * the name of a local variable.
//    * @param desc
//    * the type descriptor of this local variable.
//    * @param signature
//    * the type signature of this local variable. May be
//    * <tt>null</tt> if the local variable type does not use generic
//    * types.
//    * @param start
//    * the first instruction corresponding to the scope of this local
//    * variable (inclusive).
//    * @param end
//    * the last instruction corresponding to the scope of this local
//    * variable (exclusive).
//    * @param index
//    * the local variable's index.
//    * @throws IllegalArgumentException
//    * if one of the labels has not already been visited by this
//    * visitor (by the { @link #visitLabel visitLabel} method).
//    */
//  override def visitLocalVariable(
//      name: String,
//      desc: String,
//      signature: String,
//      start: Label,
//      end: Label,
//      index: Int): Unit = {
//    parameterIdx.get(index) match {
//      case Some((isThis, t)) =>
//        val annos = if(isThis) List(new Annotation("kind", new TokenValue("this"))) else if(t.isObject) List(objectAnnotation) else ilistEmpty
//        params += new Parameter(t, name, annos)
//        localVariables.getOrElseUpdate(index, msetEmpty) += VarScope(start, end, t, name)
//      case None =>
//        val t = JavaKnowledge.formatSignatureToType(desc)
//        localVariables.getOrElseUpdate(index, msetEmpty) += VarScope(start, end, t, name)
//    }
//  }
//
//  private def load(i: Int): (JawaType, String) = {
//    val scope = localVariables.getOrElse(i, throw DeBytecodeException(s"Failed to load idx $i")).find{ scope =>
//      scope.inScope(currentLabel)
//    }.getOrElse(throw DeBytecodeException(s"No variable found at $currentLabel for idx $i"))
//    (scope.typ, scope.name)
//  }
//
//  private val usedVariables: MMap[String, JawaType] = mmapEmpty
//
//  private def getVarType(name: String): JawaType = usedVariables.getOrElse(name, throw DeBytecodeException(s"Variable $name does not exist."))
//
//  val locals: MList[LocalVarDeclaration] = mlistEmpty
//
//  private def checkAndAddVariable(varType: JawaType): String = {
//    val expectedName = s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
//    var varName = expectedName
//    var i = 1
//    while(stackVars.contains(varName)) {
//      varName = expectedName + i
//      i += 1
//      while({
//        usedVariables.get(varName) match {
//          case Some(t) => t != varType
//          case None => false
//        }
//      }) {
//        varName = expectedName + i
//        i += 1
//      }
//    }
//    if(!usedVariables.contains(varName)) {
//      val lvd = new LocalVarDeclaration(varType, varName)
//      locals += lvd
//      usedVariables(varName) = varType
//    }
//    varName
//  }
//
//  // -------------------------------------------------------------------------
//  // Stack management
//  // -------------------------------------------------------------------------
//
//  class VariableInfo(kind: Option[Int]) {
//    var typ: JawaType = JavaKnowledge.OBJECT
////    var name: Option[String] = None
//  }
//
//  private var stackVars: IList[VariableInfo] = ilistEmpty
//
//  private def push(typ: JawaType): VariableInfo = {
//    val vi = new VariableInfo(None)
//    vi.typ = typ
//    stackVars = vi :: stackVars
//    vi
//  }
//
//  private def dup(pos: Int): Unit = {
//    require(stackVars.size >= pos, s"Stack size less than dup $pos requirement")
//    val (front, back) = stackVars.splitAt(pos)
//    stackVars = front ::: stackVars.head :: back
//  }
//
//  private def swap(): Unit = {
//    require(stackVars.size >= 2, "Stack size less than 2 for swap")
//    stackVars = stackVars.take(2).reverse ::: stackVars.drop(2)
//  }
//
//  private def pop(expectedType: Option[JawaType]): VariableInfo = {
//    require(stackVars.nonEmpty, "Stack should not be empty via pop")
//    val typ :: tail = stackVars
//    stackVars = tail
//    if(typ.typ.baseType.unknown) {
//      expectedType match {
//        case Some(e) =>
//          typ.typ = e
//        case None =>
//      }
//    }
//    typ
//  }
//
//  private val labelStack: MMap[Label, IList[VariableInfo]] = mmapEmpty
//
//  private def logStack(label: Label): Unit = labelStack(label) = stackVars
//
//  // -------------------------------------------------------------------------
//  // Instruction factory
//  // -------------------------------------------------------------------------
//
//  val objectAnnotation = new Annotation("kind", new TokenValue("object"))
//
//  import Opcodes._
//
//  trait Instruction {
//    def exec(): Unit
//  }
//
//  trait Stmt {
//    def toJawa(): Statement
//  }
//
//  case class AssignmentStmt(lhs: VariableInfo, rhs: Either[VariableInfo, ])
//
//  /**
//    * Visits a zero operand instruction.
//    *
//    * @param opcode
//    * the opcode of the instruction to be visited. This opcode is
//    * either NOP, ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1,
//    * ICONST_2, ICONST_3, ICONST_4, ICONST_5, LCONST_0, LCONST_1,
//    * FCONST_0, FCONST_1, FCONST_2, DCONST_0, DCONST_1, IALOAD,
//    * LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
//    * IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE,
//    * SASTORE, POP, POP2, DUP, DUP_X1, DUP_X2, DUP2, DUP2_X1,
//    * DUP2_X2, SWAP, IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
//    * IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV, IREM, LREM,
//    * FREM, DREM, INEG, LNEG, FNEG, DNEG, ISHL, LSHL, ISHR, LSHR,
//    * IUSHR, LUSHR, IAND, LAND, IOR, LOR, IXOR, LXOR, I2L, I2F, I2D,
//    * L2I, L2F, L2D, F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
//    * LCMP, FCMPL, FCMPG, DCMPL, DCMPG, IRETURN, LRETURN, FRETURN,
//    * DRETURN, ARETURN, RETURN, ARRAYLENGTH, ATHROW, MONITORENTER,
//    * or MONITOREXIT.
//    */
//  case class Insn(opcode: Int, vars: IList[VariableInfo]) extends Instruction {
//    def exec(): Unit = {
//      var stmt: Option[Statement] = None
//      opcode match {
//        case NOP =>
//          stmt = Some(new EmptyStatement())
//        case ACONST_NULL =>
//          val name = push(JavaKnowledge.OBJECT)
//          val ne = new NullExpression()
//          stmt = Some(new AssignmentStatement(name, ne, ilistEmpty))
//        case ICONST_M1 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, -1))
//        case ICONST_0 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 0))
//        case ICONST_1 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 1))
//        case ICONST_2 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 2))
//        case ICONST_3 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 3))
//        case ICONST_4 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 4))
//        case ICONST_5 =>
//          val name = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(name, 5))
//        case LCONST_0 =>
//          val name = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(name, 0L))
//        case LCONST_1 =>
//          val name = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(name, 1L))
//        case FCONST_0 =>
//          val name = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(name, 0F))
//        case FCONST_1 =>
//          val name = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(name, 1F))
//        case FCONST_2 =>
//          val name = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(name, 2F))
//        case DCONST_0 =>
//          val name = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(name, 0D))
//        case DCONST_1 =>
//          val name = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(name, 1D))
//        case IALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.INT)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case LALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.LONG)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case FALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.FLOAT)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case DALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.DOUBLE)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case AALOAD =>
//          val idx = pop
//          val base = pop
//          val typ = getVarType(base)
//          val tempType = JawaType.addDimensions(typ, -1)
//          val temp = push(tempType)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, List(objectAnnotation)))
//        case BALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.BOOLEAN)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case CALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.CHAR)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case SALOAD =>
//          val idx = pop
//          val base = pop
//          val temp = push(JavaKnowledge.SHORT)
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(temp, ie, ilistEmpty))
//        case IASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case LASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case FASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case DASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case AASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, List(objectAnnotation)))
//        case BASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case CASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case SASTORE =>
//          val value = pop
//          val idx = pop
//          val base = pop
//          val ie = new IndexingExpression(base, List(idx))
//          stmt = Some(new AssignmentStatement(ie, value, ilistEmpty))
//        case POP =>
//          pop
//        case POP2 =>
//          pop
//          pop
//        case DUP =>
//          dup(0)
//        case DUP_X1 =>
//          dup(1)
//        case DUP_X2 =>
//          dup(1)
//        case DUP2 =>
//          dup(0)
//        case DUP2_X1 =>
//          dup(1)
//        case DUP2_X2 =>
//          dup(1)
//        case SWAP =>
//          swap()
//        case IADD =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "+", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LADD =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "+", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case FADD =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "+", r)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case DADD =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "+", r)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case ISUB =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "-", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LSUB =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "-", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case FSUB =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "-", r)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case DSUB =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "-", r)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IMUL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "*", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LMUL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "*", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case FMUL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "*", r)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case DMUL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "*", r)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IDIV =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "/", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LDIV =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "/", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case FDIV =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "/", r)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case DDIV =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "/", r)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IREM =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "%%", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LREM =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "%%", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case FREM =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "%%", r)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case DREM =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "%%", r)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case INEG =>
//          val v = pop
//          val ue = new UnaryExpression("-", v)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
//        case LNEG =>
//          val v = pop
//          val ue = new UnaryExpression("-", v)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
//        case FNEG =>
//          val v = pop
//          val ue = new UnaryExpression("-", v)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
//        case DNEG =>
//          val v = pop
//          val ue = new UnaryExpression("-", v)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
//        case ISHL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^<", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LSHL =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^<", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case ISHR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^>", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LSHR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^>", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IUSHR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^>>", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LUSHR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^>>", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IAND =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^&", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LAND =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^&", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IOR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^|", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LOR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^|", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case IXOR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^~", r)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case LXOR =>
//          val r = pop
//          val l = pop
//          val be = new BinaryExpression(l, "^~", r)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//        case I2L =>
//          val v = pop
//          val temp = push(JavaKnowledge.LONG)
//          val ce = new CastExpression(JavaKnowledge.LONG, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case I2F =>
//          val v = pop
//          val temp = push(JavaKnowledge.FLOAT)
//          val ce = new CastExpression(JavaKnowledge.FLOAT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case I2D =>
//          val v = pop
//          val temp = push(JavaKnowledge.DOUBLE)
//          val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case L2I =>
//          val v = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CastExpression(JavaKnowledge.INT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case L2F =>
//          val v = pop
//          val temp = push(JavaKnowledge.FLOAT)
//          val ce = new CastExpression(JavaKnowledge.FLOAT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case L2D =>
//          val v = pop
//          val temp = push(JavaKnowledge.DOUBLE)
//          val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case F2I =>
//          val v = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CastExpression(JavaKnowledge.INT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case F2L =>
//          val v = pop
//          val temp = push(JavaKnowledge.LONG)
//          val ce = new CastExpression(JavaKnowledge.LONG, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case F2D =>
//          val v = pop
//          val temp = push(JavaKnowledge.DOUBLE)
//          val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case D2I =>
//          val v = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CastExpression(JavaKnowledge.INT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case D2L =>
//          val v = pop
//          val temp = push(JavaKnowledge.LONG)
//          val ce = new CastExpression(JavaKnowledge.LONG, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case D2F =>
//          val v = pop
//          val temp = push(JavaKnowledge.FLOAT)
//          val ce = new CastExpression(JavaKnowledge.FLOAT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case I2B =>
//          val v = pop
//          val temp = push(JavaKnowledge.BYTE)
//          val ce = new CastExpression(JavaKnowledge.BYTE, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case I2C =>
//          val v = pop
//          val temp = push(JavaKnowledge.CHAR)
//          val ce = new CastExpression(JavaKnowledge.CHAR, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case I2S =>
//          val v = pop
//          val temp = push(JavaKnowledge.SHORT)
//          val ce = new CastExpression(JavaKnowledge.SHORT, v)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case LCMP =>
//          val r = pop
//          val l = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CmpExpression("lcmp", l, r)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case FCMPL =>
//          val r = pop
//          val l = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CmpExpression("fcmpl", l, r)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case FCMPG =>
//          val r = pop
//          val l = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CmpExpression("fcmpg", l, r)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case DCMPL =>
//          val r = pop
//          val l = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CmpExpression("dcmpl", l, r)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case DCMPG =>
//          val r = pop
//          val l = pop
//          val temp = push(JavaKnowledge.INT)
//          val ce = new CmpExpression("dcmpg", l, r)
//          stmt = Some(new AssignmentStatement(temp, ce, ilistEmpty))
//        case IRETURN =>
//          val name = pop
//          stmt = Some(new ReturnStatement(name))
//        case LRETURN =>
//          val name = pop
//          stmt = Some(new ReturnStatement(name))
//        case FRETURN =>
//          val name = pop
//          stmt = Some(new ReturnStatement(name))
//        case DRETURN =>
//          val name = pop
//          stmt = Some(new ReturnStatement(name))
//        case ARETURN =>
//          val name = pop
//          stmt = Some(new ReturnStatement(name, List(objectAnnotation)))
//        case RETURN =>
//          stmt = Some(new ReturnStatement())
//        case ARRAYLENGTH =>
//          val name = pop
//          val len = new LengthExpression(name)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, len, ilistEmpty))
//        case ATHROW =>
//          val name = pop
//          stmt = Some(new ThrowStatement(name))
//        case MONITORENTER =>
//          val name = pop
//          stmt = Some(new MonitorStatement("monitorenter", name))
//        case MONITOREXIT =>
//          val name = pop
//          stmt = Some(new MonitorStatement("monitorexit", name))
//        case _ => throw DeBytecodeException(s"Unknown opcode for Insn: $opcode")
//      }
//      stmt match {
//        case Some(s) => createLocation(s)
//        case None =>
//      }
//    }
//  }
//
//  /**
//    * Visits an instruction with a single int operand.
//    *
//    * @param opcode
//    *            the opcode of the instruction to be visited. This opcode is
//    *            either BIPUSH, SIPUSH or NEWARRAY.
//    * @param operand
//    *            the operand of the instruction to be visited.<br>
//    *            When opcode is BIPUSH, operand value should be between
//    *            Byte.MIN_VALUE and Byte.MAX_VALUE.<br>
//    *            When opcode is SIPUSH, operand value should be between
//    *            Short.MIN_VALUE and Short.MAX_VALUE.<br>
//    *            When opcode is NEWARRAY, operand value should be one of
//    *            { @link Opcodes#T_BOOLEAN}, { @link Opcodes#T_CHAR},
//    *                    { @link Opcodes#T_FLOAT}, { @link Opcodes#T_DOUBLE},
//    *                    { @link Opcodes#T_BYTE}, { @link Opcodes#T_SHORT},
//    *                    { @link Opcodes#T_INT} or { @link Opcodes#T_LONG}.
//    */
//  case class IntInsn(opcode: Int, operand: Int) extends Instruction {
//    def exec(): Unit = {
//      val stmt: Statement = opcode match {
//        case BIPUSH =>
//          val temp = push(JavaKnowledge.INT)
//          new AssignmentStatement(temp, operand)
//        case SIPUSH =>
//          val temp = push(JavaKnowledge.INT)
//          new AssignmentStatement(temp, operand)
//        case NEWARRAY =>
//          val typ = operand match {
//            case T_BOOLEAN => JavaKnowledge.BOOLEAN
//            case T_CHAR => JavaKnowledge.CHAR
//            case T_FLOAT => JavaKnowledge.FLOAT
//            case T_DOUBLE => JavaKnowledge.DOUBLE
//            case T_BYTE => JavaKnowledge.BYTE
//            case T_SHORT => JavaKnowledge.SHORT
//            case T_INT => JavaKnowledge.INT
//            case T_LONG => JavaKnowledge.LONG
//            case _ =>  throw DeBytecodeException(s"Unknown operand for NEWARRAY: $operand")
//          }
//          val arrType = JawaType.addDimensions(typ, 1)
//          val idx = pop
//          val temp = push(arrType)
//          val nae = new NewArrayExpression(typ, List(idx))
//          new AssignmentStatement(temp, nae, ilistEmpty)
//        case _ => throw DeBytecodeException(s"Unknown opcode for IntInsn: $opcode")
//      }
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits a local variable instruction. A local variable instruction is an
//    * instruction that loads or stores the value of a local variable.
//    *
//    * @param opcode
//    * the opcode of the local variable instruction to be visited.
//    * This opcode is either ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
//    * ISTORE, LSTORE, FSTORE, DSTORE, ASTORE or RET.
//    * @param v
//    * the operand of the instruction to be visited. This operand is
//    * the index of a local variable.
//    */
//  case class VarInsn(opcode: Int, v: Int) extends Instruction {
//    def exec(): Unit = {
//      var stmt: Option[Statement] = None
//      opcode match {
//        case ILOAD =>
//          val (_, name) = load(v)
//          val temp = push(JavaKnowledge.INT)
//          stmt = Some(new AssignmentStatement(temp, name, ilistEmpty))
//        case LLOAD =>
//          val (_, name) = load(v)
//          val temp = push(JavaKnowledge.LONG)
//          stmt = Some(new AssignmentStatement(temp, name, ilistEmpty))
//        case FLOAD =>
//          val (_, name) = load(v)
//          val temp = push(JavaKnowledge.FLOAT)
//          stmt = Some(new AssignmentStatement(temp, name, ilistEmpty))
//        case DLOAD =>
//          val (_, name) = load(v)
//          val temp = push(JavaKnowledge.DOUBLE)
//          stmt = Some(new AssignmentStatement(temp, name, ilistEmpty))
//        case ALOAD =>
//          val (t, name) = load(v)
//          val temp = push(t)
//          stmt = Some(new AssignmentStatement(temp, name, List(objectAnnotation)))
//        case ISTORE =>
//          val temp = pop
//          val typ = getVarType(temp)
//          val name = store(v, typ)
//          stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
//        case LSTORE =>
//          val temp = pop
//          val typ = getVarType(temp)
//          val name = store(v, typ)
//          stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
//        case FSTORE =>
//          val temp = pop
//          val typ = getVarType(temp)
//          val name = store(v, typ)
//          stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
//        case DSTORE =>
//          val temp = pop
//          val typ = getVarType(temp)
//          val name = store(v, typ)
//          stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
//        case ASTORE =>
//          val temp = pop
//          val typ = getVarType(temp)
//          val name = store(v, typ)
//          stmt = Some(new AssignmentStatement(name, temp, List(objectAnnotation)))
//        //      case RET =>
//        case _ => throw DeBytecodeException(s"Unknown opcode for VarInsn: $opcode")
//      }
//      stmt match {
//        case Some(s) =>
//          createLocation(s)
//        case None =>
//      }
//    }
//  }
//
//  /**
//    * Visits a type instruction. A type instruction is an instruction that
//    * takes the internal name of a class as parameter.
//    *
//    * @param opcode
//    * the opcode of the type instruction to be visited. This opcode
//    * is either NEW, ANEWARRAY, CHECKCAST or INSTANCEOF.
//    * @param t
//    * the operand of the instruction to be visited. This operand
//    * must be the internal name of an object or array class (see
//    * { @link Type#getInternalName() getInternalName}).
//    */
//  case class TypeInsn(opcode: Int, t: String) extends Instruction {
//    def exec(): Unit = {
//      val typ = JavaKnowledge.getTypeFromName(getClassName(t))
//      val stmt: Statement = opcode match {
//        case NEW =>
//          val temp = push(typ)
//          val ne = new NewExpression(typ)
//          new AssignmentStatement(temp, ne, ilistEmpty)
//        case ANEWARRAY =>
//          val idx = pop
//          val arrType = JawaType.addDimensions(typ, 1)
//          val temp = push(arrType)
//          val ne = new NewArrayExpression(typ, List(idx))
//          new AssignmentStatement(temp, ne, ilistEmpty)
//        case CHECKCAST =>
//          val v = pop
//          val temp = push(typ)
//          val ce = new CastExpression(typ, v)
//          new AssignmentStatement(temp, ce, List(objectAnnotation))
//        case INSTANCEOF =>
//          val v = pop
//          val temp = push(JavaKnowledge.BOOLEAN)
//          val ioe = new InstanceOfExpression(v, typ)
//          new AssignmentStatement(temp, ioe, ilistEmpty)
//        case _ => throw DeBytecodeException(s"Unknown opcode for TypeInsn: $opcode")
//      }
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits a field instruction. A field instruction is an instruction that
//    * loads or stores the value of a field of an object.
//    *
//    * @param opcode
//    * the opcode of the type instruction to be visited. This opcode
//    * is either GETSTATIC, PUTSTATIC, GETFIELD or PUTFIELD.
//    * @param owner
//    * the internal name of the field's owner class (see
//    * { @link Type#getInternalName() getInternalName}).
//    * @param name
//    * the field's name.
//    * @param desc
//    * the field's descriptor (see { @link Type Type}).
//    */
//  case class FieldInsn(opcode: Int, owner: String, name: String, desc: String) extends Instruction {
//    def exec(): Unit = {
//      val fqn = FieldFQN(JavaKnowledge.getTypeFromName(getClassName(owner)), name, JavaKnowledge.formatSignatureToType(desc))
//      val annotations: MList[Annotation] = mlistEmpty
//      if(fqn.typ.isObject) {
//        annotations += objectAnnotation
//      }
//      val stmt: Statement = opcode match {
//        case GETSTATIC =>
//          val temp = push(fqn.typ)
//          val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
//          new AssignmentStatement(temp, f, annotations.toList)
//        case PUTSTATIC =>
//          val temp = pop
//          val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
//          new AssignmentStatement(f, temp, annotations.toList)
//        case GETFIELD =>
//          val base = pop
//          val temp = push(fqn.typ)
//          val f = new AccessExpression(base, fqn.fqn, fqn.typ)
//          new AssignmentStatement(temp, f, annotations.toList)
//        case PUTFIELD =>
//          val temp = pop
//          val base = pop
//          val f = new AccessExpression(base, fqn.fqn, fqn.typ)
//          new AssignmentStatement(f, temp, annotations.toList)
//        case _ => throw DeBytecodeException(s"Unknown opcode for FieldInsn: $opcode")
//      }
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits a method instruction. A method instruction is an instruction that
//    * invokes a method.
//    *
//    * @param opcode
//    * the opcode of the type instruction to be visited. This opcode
//    * is either INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC or
//    * INVOKEINTERFACE.
//    * @param owner
//    * the internal name of the method's owner class (see
//    * { @link Type#getInternalName() getInternalName}).
//    * @param name
//    * the method's name.
//    * @param desc
//    * the method's descriptor (see { @link Type Type}).
//    * @param itf
//    * if the method's owner class is an interface.
//    */
//  case class MethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean) extends Instruction {
//    def exec(): Unit = {
//      val typ = JavaKnowledge.getTypeFromName(getClassName(owner))
//      val sig = new Signature(typ, name, desc)
//      val stmt: Statement = opcode match {
//        case INVOKEVIRTUAL =>
//          val argNum = sig.getParameterNum + 1
//          val argNames = (0 until argNum).map(_ => pop).reverse.toList
//          val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
//            Some(push(sig.getReturnType))
//          } else {
//            None
//          }
//          new CallStatement(retVar, name, argNames, sig, "virtual")
//        case INVOKESPECIAL =>
//          val argNum = sig.getParameterNum + 1
//          val argNames = (0 until argNum).map(_ => pop).reverse.toList
//          val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
//            Some(push(sig.getReturnType))
//          } else {
//            None
//          }
//          new CallStatement(retVar, name, argNames, sig, "direct")
//        case INVOKESTATIC =>
//          val argNum = sig.getParameterNum
//          val argNames = (0 until argNum).map(_ => pop).reverse.toList
//          val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
//            Some(push(sig.getReturnType))
//          } else {
//            None
//          }
//          new CallStatement(retVar, name, argNames, sig, "static")
//        case INVOKEINTERFACE =>
//          val argNum = sig.getParameterNum + 1
//          val argNames = (0 until argNum).map(_ => pop).reverse.toList
//          val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
//            Some(push(sig.getReturnType))
//          } else {
//            None
//          }
//          new CallStatement(retVar, name, argNames, sig, "interface")
//        case _ => throw DeBytecodeException(s"Unknown opcode for MethodInsn: $opcode")
//      }
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits an invokedynamic instruction.
//    *
//    * @param name
//    * the method's name.
//    * @param desc
//    * the method's descriptor (see { @link Type Type}).
//    * @param bsm
//    * the bootstrap method.
//    * @param bsmArgs
//    * the bootstrap method constant arguments. Each argument must be
//    * an { @link Integer}, { @link Float}, { @link Long},
//    *            { @link Double}, { @link String}, { @link Type} or { @link Handle}
//    *            value. This method is allowed to modify the content of the
//    *            array so a caller should expect that this array may change.
//    */
//  case class InvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*) extends Instruction {
//    def exec(): Unit = {
//      //TODO
//      throw DeBytecodeException(s"Unhandled InvokeDynamicInsn")
//    }
//  }
//
//  /**
//    * Visits a jump instruction. A jump instruction is an instruction that may
//    * jump to another instruction.
//    *
//    * @param opcode
//    * the opcode of the type instruction to be visited. This opcode
//    * is either IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IF_ICMPEQ,
//    * IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
//    * IF_ACMPEQ, IF_ACMPNE, GOTO, JSR, IFNULL or IFNONNULL.
//    * @param label
//    * the operand of the instruction to be visited. This operand is
//    * a label that designates the instruction to which the jump
//    * instruction may jump.
//    */
//  case class JumpInsn(opcode: Int, label: Label) extends Instruction {
//    def exec(): Unit = {
//      val stmt: Statement = opcode match {
//        case IFEQ =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "==", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFNE =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "!=", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFLT =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "<", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFGE =>
//          val cond = pop
//          val be = new BinaryExpression(cond, ">=", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFGT =>
//          val cond = pop
//          val be = new BinaryExpression(cond, ">", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFLE =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "<=", new LiteralExpression(0))
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPEQ =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "==", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPNE =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "!=", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPLT =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "<", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPGE =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, ">=", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPGT =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, ">", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ICMPLE =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "<=", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ACMPEQ =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "==", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IF_ACMPNE =>
//          val right = pop
//          val left = pop
//          val be = new BinaryExpression(left, "!=", right)
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case GOTO =>
//          val (l, _, _) = handleLabel(label)
//          new GotoStatement(l)
//        //      case JSR =>
//        case IFNULL =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "==")
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case IFNONNULL =>
//          val cond = pop
//          val be = new BinaryExpression(cond, "!=")
//          val (l, _, _) = handleLabel(label)
//          new IfStatement(be, l)
//        case _ => throw DeBytecodeException(s"Unknown opcode for JumpInsn: $opcode")
//      }
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits a LDC instruction. Note that new constant types may be added in
//    * future versions of the Java Virtual Machine. To easily detect new
//    * constant types, implementations of this method should check for
//    * unexpected constant types, like this:
//    *
//    * <pre>
//    * if (cst instanceof Integer) {
//    * // ...
//    * } else if (cst instanceof Float) {
//    * // ...
//    * } else if (cst instanceof Long) {
//    * // ...
//    * } else if (cst instanceof Double) {
//    * // ...
//    * } else if (cst instanceof String) {
//    * // ...
//    * } else if (cst instanceof Type) {
//    * int sort = ((Type) cst).getSort();
//    * if (sort == Type.OBJECT) {
//    * // ...
//    * } else if (sort == Type.ARRAY) {
//    * // ...
//    * } else if (sort == Type.METHOD) {
//    * // ...
//    * } else {
//    * // throw an exception
//    * }
//    * } else if (cst instanceof Handle) {
//    * // ...
//    * } else {
//    * // throw an exception
//    * }
//    * </pre>
//    *
//    * @param cst
//    * the constant to be loaded on the stack. This parameter must be
//    * a non null { @link Integer}, a { @link Float}, a { @link Long}, a
//    *                    { @link Double}, a { @link String}, a { @link Type} of OBJECT or
//    *                    ARRAY sort for <tt>.class</tt> constants, for classes whose
//    *                    version is 49.0, a { @link Type} of METHOD sort or a
//    *                    { @link Handle} for MethodType and MethodHandle constants, for
//    *                    classes whose version is 51.0.
//    */
//  case class LdcInsn(cst: Any) extends Instruction {
//    def exec(): Unit = {
//      val (typ, expr) = cst.getClass.getName match {
//        case "java.lang.Integer" =>
//          val le = new LiteralExpression(cst.asInstanceOf[java.lang.Integer].intValue())
//          (JavaKnowledge.INT, le)
//        case "java.lang.Float" =>
//          val le = new LiteralExpression(cst.asInstanceOf[java.lang.Float].floatValue())
//          (JavaKnowledge.FLOAT, le)
//        case "java.lang.Long" =>
//          val le = new LiteralExpression(cst.asInstanceOf[java.lang.Long].longValue())
//          (JavaKnowledge.LONG, le)
//        case "java.lang.Double" =>
//          val le = new LiteralExpression(cst.asInstanceOf[java.lang.Double].doubleValue())
//          (JavaKnowledge.DOUBLE, le)
//        case "java.lang.String" =>
//          val le = new LiteralExpression(cst.asInstanceOf[java.lang.String])
//          (JavaKnowledge.STRING, le)
//        case "org.objectweb.asm.Type" =>
//          val asmType = cst.asInstanceOf[org.objectweb.asm.Type]
//          val t = Option(asmType.getClassName) match {
//            case Some(cn) => // class type
//              JavaKnowledge.getTypeFromJawaName(cn)
//            case None => // method type
//              throw DeBytecodeException(s"Method type is not handled: $cst")
//          }
//          val ce = new ConstClassExpression(t)
//          (JavaKnowledge.CLASS, ce)
//        case "org.objectweb.asm.Handle" =>
//          throw DeBytecodeException(s"Handle is not handled: $cst")
//        case _ => throw DeBytecodeException(s"Unknown opcode for LdcInsn: $cst")
//      }
//      val temp = push(typ)
//      val stmt = new AssignmentStatement(temp, expr, ilistEmpty)
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits an IINC instruction.
//    *
//    * @param v
//    * index of the local variable to be incremented.
//    * @param increment
//    * amount to increment the local variable by.
//    */
//  case class IincInsn(v: Int, increment: Int) extends Instruction {
//    def exec(): Unit = {
//      val (_, name) = load(v)
//      val negative = Math.signum(increment) == -1
//      val num = Math.abs(increment)
//      val op = if(negative) "-" else "+"
//      val be = new BinaryExpression(name, op, new LiteralExpression(num))
//      val stmt = new AssignmentStatement(name, be, ilistEmpty)
//      createLocation(stmt)
//    }
//  }
//
//  /**
//    * Visits a TABLESWITCH instruction.
//    *
//    * @param min
//    * the minimum key value.
//    * @param max
//    * the maximum key value.
//    * @param dflt
//    * beginning of the default handler block.
//    * @param labels
//    * beginnings of the handler blocks. <tt>labels[i]</tt> is the
//    * beginning of the handler block for the <tt>min + i</tt> key.
//    */
//  case class TableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*) extends Instruction {
//    def exec(): Unit = {
//      val cond = pop
//      val cases: IList[SwitchCase] = (min to max).map { i =>
//        val idx = i - min
//        val label = labels(idx)
//        val (l, _, _) = handleLabel(label)
//        new SwitchCase(i, l)
//      }.toList
//      val (dl, _, _) = handleLabel(dflt)
//      val defaultCase = new SwitchDefaultCase(dl)
//      val ss = new SwitchStatement(cond, cases, defaultCase)
//      createLocation(ss)
//    }
//  }
//
//  /**
//    * Visits a LOOKUPSWITCH instruction.
//    *
//    * @param dflt
//    * beginning of the default handler block.
//    * @param keys
//    * the values of the keys.
//    * @param labels
//    * beginnings of the handler blocks. <tt>labels[i]</tt> is the
//    * beginning of the handler block for the <tt>keys[i]</tt> key.
//    */
//  case class LookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]) extends Instruction {
//    def exec(): Unit = {
//      val cond = pop
//      val cases: IList[SwitchCase] = keys.indices.map { i =>
//        val key = keys(i)
//        val label = labels(i)
//        val (l, _, _) = handleLabel(label)
//        new SwitchCase(key, l)
//      }.toList
//      val (dl, _, _) = handleLabel(dflt)
//      val defaultCase = new SwitchDefaultCase(dl)
//      val ss = new SwitchStatement(cond, cases, defaultCase)
//      createLocation(ss)
//    }
//  }
//
//  /**
//    * Visits a MULTIANEWARRAY instruction.
//    *
//    * @param desc
//    * an array type descriptor (see { @link Type Type}).
//    * @param dims
//    * number of dimensions of the array to allocate.
//    */
//  case class MultiANewArrayInsn(desc: String, dims: Int) extends Instruction {
//    def exec(): Unit = {
//      val typ = JavaKnowledge.formatSignatureToType(desc)
//      val idxs = (0 until dims).map(_ => pop).reverse.toList
//      val temp = push(typ)
//      val arrayType = JawaType.addDimensions(typ, -1)
//      val ne = new NewArrayExpression(arrayType, idxs)
//      val stmt = new AssignmentStatement(temp, ne, ilistEmpty)
//      createLocation(stmt)
//    }
//  }
//
//  case class LabelInsn(label: Label) extends Instruction {
//    def exec(): Unit = {
//      val (l, es, newstack) = handleLabel(label)
//      stackVars = newstack
//      val loc = new Location(l, es)
//      loc.locationSymbol.locationIndex = line
//      locations += loc
//      exceptionHandler.get(label) match {
//        case Some(t) =>
//          val temp = push(t)
//          val ee = new ExceptionExpression(t)
//          val stmt = new AssignmentStatement(temp, ee, List(objectAnnotation))
//          createLocation(stmt)
//        case None =>
//      }
//    }
//  }
//
//  private val insns: MList[Instruction] = mlistEmpty
//
//  // -------------------------------------------------------------------------
//  // Normal instructions
//  // -------------------------------------------------------------------------
//
//  override def visitInsn(opcode: Int): Unit = {
//    insns += Insn(opcode)
//  }
//
//  override def visitIntInsn(opcode: Int, operand: Int): Unit = {
//    insns += IntInsn(opcode, operand)
//  }
//
//  override def visitVarInsn(opcode: Int, v: Int): Unit = {
//    insns += VarInsn(opcode, v)
//  }
//
//  override def visitTypeInsn(opcode: Int, t: String): Unit = {
//    insns += TypeInsn(opcode, t)
//  }
//
//
//  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
//    insns += FieldInsn(opcode, owner, name, desc)
//  }
//
//  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
//    insns += MethodInsn(opcode, owner, name, desc, itf)
//  }
//
//
//  override def visitInvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*): Unit = {
//    insns += InvokeDynamicInsn(name, desc, bsm, bsmArgs)
//  }
//
//  override def visitJumpInsn(opcode: Int, label: Label): Unit = {
//    insns += JumpInsn(opcode, label)
//  }
//
//  // -------------------------------------------------------------------------
//  // Special instructions
//  // -------------------------------------------------------------------------
//
//  override def visitLdcInsn(cst: Any): Unit = {
//    insns += LdcInsn(cst)
//  }
//
//  override def visitIincInsn(v: Int, increment: Int): Unit = {
//    insns += IincInsn(v, increment)
//  }
//
//  override def visitTableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*): Unit = {
//    insns += TableSwitchInsn(min, max, dflt, labels)
//  }
//
//  override def visitLookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]): Unit = {
//    insns += LookupSwitchInsn(dflt, keys, labels)
//  }
//
//  override def visitMultiANewArrayInsn(desc: String, dims: Int): Unit = {
//    insns += MultiANewArrayInsn(desc, dims)
//  }
//
//  // -------------------------------------------------------------------------
//  // Exceptions table entries
//  // -------------------------------------------------------------------------
//
//  private val exceptionHandler: MMap[Label, JawaType] = mmapEmpty
//
//  private val catchClauses: MList[CatchClause] = mlistEmpty
//
//  /**
//    * Visits a try catch block.
//    *
//    * @param start
//    * beginning of the exception handler's scope (inclusive).
//    * @param end
//    * end of the exception handler's scope (exclusive).
//    * @param handler
//    * beginning of the exception handler's code.
//    * @param t
//    * internal name of the type of exceptions handled by the
//    * handler, or <tt>null</tt> to catch any exceptions (for
//    * "finally" blocks).
//    * @throws IllegalArgumentException
//    * if one of the labels has already been visited by this visitor
//    * (by the { @link #visitLabel visitLabel} method).
//    */
//  override def visitTryCatchBlock(start: Label, end: Label, handler: Label, t: String): Unit = {
//    val typ: JawaType = Option(t) match {
//      case Some(str) => JavaKnowledge.getTypeFromName(getClassName(str))
//      case None => ExceptionCenter.THROWABLE
//    }
//    val (from, _, _) = handleLabel(start)
//    val (to, _, _) = handleLabel(end)
//    val (target, _, _) = handleLabel(handler)
//    exceptionHandler(handler) = typ
//    catchClauses += new CatchClause(typ, from, to, target)
//  }
//
//  // -------------------------------------------------------------------------
//  // Location
//  // -------------------------------------------------------------------------
//
//  private var locCount: Int = 0
//  private def line: Int = labelCount + locCount
//
//  val locations: MList[Location] = mlistEmpty
//
//  private def createLocation(stmt: Statement): Unit = {
//    val l = s"L$locCount"
//    val loc = new Location(l, stmt)
//    loc.locationSymbol.locationIndex = line
//    locations += loc
//    locCount += 1
//  }
//
//  override def visitEnd(): Unit = {
//    val body: Body = ResolvedBody(locals.toList, locations.toList, catchClauses.toList)(NoPosition)
//    val md = MethodDeclaration(returnType, methodSymbol, params.toList, annotations, body)(NoPosition)
//    md.getAllChildren foreach {
//      case vd: VarDefSymbol => vd.owner = md
//      case vs: VarSymbol => vs.owner = md
//      case ld: LocationDefSymbol => ld.owner = md
//      case ls: LocationSymbol => ls.owner = md
//      case _ =>
//    }
//    methods += md
//  }
//}
