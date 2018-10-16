/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.parser

import org.argus.jawa.core.ast._
import org.argus.jawa.core.compiler.lexer._
import org.argus.jawa.core.compiler.lexer.Tokens._
import org.argus.jawa.core.io.{DefinedPosition, NoPosition, Position, Reporter, SourceFile}
import org.argus.jawa.core.elements.JavaKnowledge
import org.argus.jawa.core.util._

import scala.util.{Failure, Success, Try}

class JawaParser(tokens: Array[Token], reporter: Reporter) extends JavaKnowledge {

  private val logging: Boolean = false

  def safeParse[T <: ParsableAstNode](production: => T): Option[T] = try Some(production) catch { case _: JawaParserException => None }

  require(!tokens.isEmpty) // at least EOF

  def getPos(firstPos: Position, lastPos: Position): Position = {
    if(tokens.isEmpty) NoPosition
    else {
      val firstIndex = firstPos.start
      val lastIndex = lastPos.end
      Position.range(firstPos.source, firstIndex, lastIndex - firstIndex + 1)
    }
  }

  def compilationUnit(resolveBody: Boolean): CompilationUnit = {
    val topDecls: MList[ClassOrInterfaceDeclaration] = mlistEmpty
    def loop() {
      currentTokenType match {
        case CLASS_OR_INTERFACE =>
          topDecls += classOrInterfaceDeclaration0(resolveBody)
          loop()
        case _ =>
      }
    }
    loop()
    val eof = accept(EOF)
    val cu = CompilationUnit(topDecls.toList)(getPos(topDecls.head.pos, eof.pos))
    cu.topDecls foreach { cid =>
      val typ = cid.cityp
      cid.getAllChildrenInclude foreach (_.enclosingTopLevelClass = typ)
    }
    cu
  }
  
  def classOrInterfaceDeclaration(resolveBody: Boolean): ClassOrInterfaceDeclaration = classOrInterfaceDeclaration0(resolveBody)
  
  private def classOrInterfaceDeclaration0(resolveBody: Boolean): ClassOrInterfaceDeclaration = {
    val coi = accept(CLASS_OR_INTERFACE)
    val cityp: TypeDefSymbol = typeDefSymbol()
    val annotations_ : IList[Annotation] = annotations()
    val extendsAndImplimentsClausesOpt_ : Option[ExtendsAndImplementsClauses] = extendsAndImplementsClausesOpt()
    accept(LBRACE)
    val instanceFields: IList[InstanceFieldDeclaration] = instanceFieldDeclarations()
    val rbrace = accept(RBRACE)
    val staticFields: IList[StaticFieldDeclaration] = staticFieldDeclarations()
    val methods: IList[MethodDeclaration] = methodDeclarations(resolveBody)
    val lastPos = methods.lastOption match {
      case Some(m) => m.pos
      case None =>
        staticFields.lastOption match {
          case Some(f) => f.pos
          case None =>
            rbrace.pos
        }
    }
    ClassOrInterfaceDeclaration(cityp, annotations_, extendsAndImplimentsClausesOpt_, instanceFields, staticFields, methods)(getPos(coi.pos, lastPos))
  }

  private def annotation(): Annotation = {
    val at = accept(AT)
    val annotationID: Token = accept(ID)
    var lastPos: Position = annotationID.pos
    val annotationValueOpt: Option[AnnotationValue] = currentTokenType match {
      case LPAREN =>
        val lparen = accept(LPAREN)
        val statements: MList[Statement] = mlistEmpty
        while(currentTokenType != RPAREN) {
          val statement_ : Statement = statement()
          currentTokenType match {
            case COMMA => nextToken()
            case _ =>
          }
          statements += statement_
        }
        val rparen = accept(RPAREN)
        Some(StatementValue(statements.toList)(getPos(lparen.pos, rparen.pos)))
      case _ =>
        annotationID.text match {
          case "type" =>
            val te = typExpression()
            Some(TypeExpressionValue(te)(te.pos))
          case "signature" =>
            val ss = signatureSymbol()
            Some(SymbolValue(ss)(ss.pos))
          case _ =>
            currentTokenType match{
              case ID =>
                val t = nextToken()
                Some(TokenValue(t)(t.pos))
              case x if isLiteralToken(x) =>
                val t = nextToken()
                Some(TokenValue(t)(t.pos))
              case _ => None
            }
        }
    }
    annotationValueOpt match {
      case Some(v) => lastPos = v.pos
      case None =>
    }
    Annotation(annotationID, annotationValueOpt)(getPos(at.pos, lastPos))
  }
  
  private def annotations(): IList[Annotation] = {
    val annos: MList[Annotation] = mlistEmpty
    def loop(){
      currentTokenType match {
        case AT =>
          val anno = annotation()
          annos += anno
          loop()
        case _ =>
      }
    }
    loop()
    annos.toList
  }
  
  private def typeDefSymbol(): TypeDefSymbol = {
    val id = accept(ID)
    TypeDefSymbol(id)(id.pos)
  }
  
  private def typeSymbol(): TypeSymbol = {
    val id = accept(ID)
    TypeSymbol(id)(id.pos)
  }
  
  private def methodDefSymbol(): MethodDefSymbol = {
    val id = accept(ID)
    MethodDefSymbol(id)(id.pos)
  }
  
  private def methodNameSymbol(): MethodNameSymbol = {
    val id = accept(ID)
    MethodNameSymbol(id)(id.pos)
  }
  
  private def fieldDefSymbol(): FieldDefSymbol = {
    val id = accept(ID)
    FieldDefSymbol(id)(id.pos)
  }
  
  private def staticFieldDefSymbol(): FieldDefSymbol = {
    val id = accept(STATIC_ID)
    FieldDefSymbol(id)(id.pos)
  }
  
  private def fieldNameSymbol(): FieldNameSymbol = {
    val id = accept(ID)
    FieldNameSymbol(id)(id.pos)
  }
  
  private def staticFieldNameSymbol(): FieldNameSymbol = {
    val id = accept(STATIC_ID)
    FieldNameSymbol(id)(id.pos)
  }
  
  private def signatureSymbol(): SignatureSymbol = {
    val id = accept(ID)
    SignatureSymbol(id)(id.pos)
  }
  
  private def varDefSymbol(): VarDefSymbol = {
    val id = accept(ID)
    VarDefSymbol(id)(id.pos)
  }
  
  private def varSymbol(): VarSymbol = {
    val id = accept(ID)
    VarSymbol(id)(id.pos)
  }
  
  private def locationDefSymbol(): LocationDefSymbol = {
    val id = accept(LOCATION_ID)
    LocationDefSymbol(id)(id.pos)
  }
  
  private def locationSymbol(): LocationSymbol = {
    val id = accept(ID)
    LocationSymbol(id)(id.pos)
  }
  
  private def extendsAndImplementsClausesOpt(): Option[ExtendsAndImplementsClauses] = {
    currentTokenType match {
      case EXTENDS_AND_IMPLEMENTS =>
        val eai = accept(EXTENDS_AND_IMPLEMENTS)
        val parents: MList[ExtendAndImplement] = mlistEmpty
        def loop() {
          val parent : ExtendAndImplement = extendAndImplement()
          currentTokenType match {
            case COMMA =>
              nextToken()
              parents += parent
              loop()
            case _ =>
              parents += parent
          }
        }
        loop()
        val lastPos = parents.lastOption match {
          case Some(p) => p.pos
          case None => eai.pos
        }
        Some(ExtendsAndImplementsClauses(parents.toList)(getPos(eai.pos, lastPos)))
      case _ => None
    }
  }
  
  private def extendAndImplement(): ExtendAndImplement = {
    val parenttyp: TypeSymbol = typeSymbol()
    val annotations_ : IList[Annotation] = annotations()
    val lastPos = annotations_.lastOption match {
      case Some(a) => a.pos
      case None => parenttyp.pos
    }
    ExtendAndImplement(parenttyp, annotations_)(getPos(parenttyp.pos, lastPos))
  }
  
  private def instanceFieldDeclarations(): IList[InstanceFieldDeclaration] = {
    val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
    while(currentTokenType != RBRACE){
      val typ_ : Type = typ()
      val defSymbol: FieldDefSymbol = fieldDefSymbol()
      val annotations_ = annotations()
      val semi = accept(SEMI)
      instanceFields += InstanceFieldDeclaration(typ_, defSymbol, annotations_)(getPos(typ_.pos, semi.pos))
    }
    instanceFields.toList
  }
  
  private def staticFieldDeclarations(): IList[StaticFieldDeclaration] = {
    val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
    def loop(){
      currentTokenType match {
        case STATIC_FIELD =>
          val sf = accept(STATIC_FIELD)
          val typ_ : Type = typ()
          val defSymbol: FieldDefSymbol = staticFieldDefSymbol()
          val annotations_ = annotations()
          val semi = accept(SEMI)
          staticFields += StaticFieldDeclaration(typ_, defSymbol, annotations_)(getPos(sf.pos, semi.pos))
          loop()
        case _ =>
      }
    }
    loop()
    staticFields.toList
  }
  
  private def methodDeclarations(resolveBody: Boolean): IList[MethodDeclaration] = {
    val methods: MList[MethodDeclaration] = mlistEmpty
    def loop() {
      currentTokenType match {
        case METHOD =>
          val method = methodDeclaration0(resolveBody)
          methods += method
          loop()
        case _ =>
      }
    }
    loop()
    methods.toList
  }
  
  def methodDeclaration(resolveBody: Boolean): MethodDeclaration = methodDeclaration0(resolveBody)
  
  private def methodDeclaration0(resolveBody: Boolean): MethodDeclaration = {
    val method = accept(METHOD)
    val returnType: Type = typ()
    val defSymbol: MethodDefSymbol = methodDefSymbol()
    accept(LPAREN)
    val params: MList[Parameter] = mlistEmpty
    while(currentTokenType != RPAREN) {
      val param_ : Parameter = param()
      currentTokenType match {
        case COMMA => nextToken()
        case _ =>
      }
      params += param_
    }
    accept(RPAREN)
    val annotations_ : IList[Annotation] = annotations()
    val body_ : Body = body0(resolveBody)
    val md = MethodDeclaration(returnType, defSymbol, params.toList, annotations_, body_)(getPos(method.pos, body_.pos))
    defSymbol.signature = md.signature
    md.getAllChildren foreach {
      case vd: VarDefSymbol => vd.owner = md
      case vs: VarSymbol => vs.owner = md
      case ld: LocationDefSymbol => ld.owner = md
      case ls: LocationSymbol => ls.owner = md
      case _ =>
    }
    md
  }
  
  private def param(): Parameter = {
    val typ_ : Type = typ()
    val defSymbol: VarDefSymbol = varDefSymbol()
    val annotations_ = annotations()
    val lastPos = annotations_.lastOption match {
      case Some(a) => a.pos
      case None => defSymbol.pos
    }
    Parameter(typ_, defSymbol, annotations_)(getPos(typ_.pos, lastPos))
  }
  
  def body(resolveBody: Boolean): Body = body0(resolveBody)
  
  private def body0(resolveBody: Boolean): Body = {
    if(resolveBody) {
      val lbrace = accept(LBRACE)
      val locals: IList[LocalVarDeclaration] = localVarDeclarations()
      val locations_ : IList[Location] = locations()
      val catchClauses_ : IList[CatchClause] = catchClauses()
      val rbrace = accept(RBRACE)
      val rb = ResolvedBody(locals, locations_, catchClauses_)(getPos(lbrace.pos, rbrace.pos))
      val locationSymbols: MSet[LocationSymbol] = msetEmpty
      rb.catchClauses.foreach { cc =>
        locationSymbols += cc.range.fromLocation
        locationSymbols += cc.range.toLocation
        locationSymbols += cc.targetLocation
      }
      locationSymbols.foreach { ls =>
        rb.locations.find(l => l.locationUri == ls.location) foreach { l =>
          ls.locationIndex = l.locationIndex
        }
      }
      locationSymbols.clear()
      rb.locations foreach { l =>
        l.statement match {
          case is: IfStatement => locationSymbols += is.targetLocation
          case gs: GotoStatement => locationSymbols += gs.targetLocation
          case ss: SwitchStatement =>
            ss.cases.foreach { ss_case =>
              locationSymbols += ss_case.targetLocation
            }
            ss.defaultCaseOpt.foreach { ss_def =>
              locationSymbols += ss_def.targetLocation
            }
          case _ =>
        }
      }
      locationSymbols.foreach { ls =>
        rb.locations.find(l => l.locationUri == ls.location) foreach { l =>
          ls.locationIndex = l.locationIndex
        }
      }
      rb
    } else {
      val bodytokens: MList[Token] = mlistEmpty
      var stop: Boolean = false
      do {
        bodytokens += nextToken()
        stop = currentTokenType == EOF || currentTokenType == METHOD || currentTokenType == CLASS_OR_INTERFACE
      } while (!stop)
      UnresolvedBodyJawa(bodytokens.toList)(getPos(bodytokens.head.pos, bodytokens.last.pos))
    } 
  }
  
  private def localVarDeclarations(): IList[LocalVarDeclaration] = {
    val locals: MList[LocalVarDeclaration] = mlistEmpty
    while(currentTokenType != LOCATION_ID && currentTokenType != RBRACE && currentTokenType != CATCH){
      val ahead1 = lookahead(1)
      val typOpt: Option[Type] = ahead1 match {
        case SEMI =>
          None
        case _ =>
          Some(typ())
      }
      val varSymbol_ : VarDefSymbol = varDefSymbol()
      val semi = accept(SEMI)
      val firstPos = locals.headOption match {
        case Some(l) => l.pos
        case None => varSymbol_.pos
      }
      locals += LocalVarDeclaration(typOpt, varSymbol_)(getPos(firstPos, semi.pos))
    }
    locals.toList
  }
  
  private def locations(): IList[Location] = {
    val locations: MList[Location] = mlistEmpty
    def loop(){
      currentTokenType match {
        case LOCATION_ID =>
          val index = locations.size
          locations += location0(index)
          loop()
        case _ =>
      }
    }
    loop()
    locations.toList
  }
  
  def location: Location = location0()
  
  private def location0(index: Int = 0): Location = {
    val locationSymbol_ : LocationDefSymbol = locationDefSymbol()
    locationSymbol_.locationIndex = index
    var lastPos: Position = locationSymbol_.pos
    val statement_ : Statement = statement()
    statement_.pos match {
      case dp: DefinedPosition => lastPos = dp
      case _ =>
    }
    currentTokenType match {
      case SEMI =>
        val semi = nextToken()
        lastPos = semi.pos
      case _ =>
    }
    Location(locationSymbol_, statement_)(getPos(locationSymbol_.pos, lastPos))
  }
  
  private def statement(): Statement = {
    currentTokenType match {
      case CALL => callStatement()
      case THROW => throwStatement()
      case IF => ifStatement()
      case SWITCH => switchStatement()
      case RETURN => returnStatement()
      case GOTO => gotoStatement()
      case AT if lookahead(1) == MONITOR_ENTER || lookahead(1) == MONITOR_EXIT => monitorStatement()
      case AT | SEMI | LOCATION_ID | RBRACE | CATCH => emptyStatement()
      case _ => assignmentStatement()
    }
  }
  
  private def callStatement(): CallStatement = {
    val call = accept(CALL)
    val ahead2 = lookahead(1)
    val lhsOpt: Option[VariableNameExpression] = ahead2 match {
      case ASSIGN_OP =>
        val lhs = variableNameExpression()
        accept(ASSIGN_OP)
        Some(lhs)
      case _ => None
    }
    val rhs: CallRhs = callRhs()
    val annotations_ : IList[Annotation] = annotations()
    val lastPos = annotations_.lastOption match {
      case Some(a) => a.pos
      case None => rhs.pos
    }
    val cs = CallStatement(lhsOpt, rhs, annotations_)(getPos(call.pos, lastPos))
    rhs.methodNameSymbol.signature = cs.signature
    cs
  }

  private def callRhs(): CallRhs = {
    val nameSymbol: MethodNameSymbol = methodNameSymbol()
    accept(LPAREN)
    val varIDs: MList[VarSymbol] = mlistEmpty
    while(currentTokenType != RPAREN) {
      val varSymbol_ : VarSymbol = varSymbol()
      currentTokenType match {
        case COMMA => nextToken()
        case _ =>
      }
      varIDs += varSymbol_
    }
    val rparen = accept(RPAREN)
    CallRhs(nameSymbol, varIDs.toList)(getPos(nameSymbol.pos, rparen.pos))
  }
  
  private def assignmentStatement(): AssignmentStatement = {
    val lhs: Expression with LHS = expression_lhs()
    accept(ASSIGN_OP)
    val rhs: Expression with RHS = expression_rhs()
    val annotations_ : IList[Annotation] = annotations()
    val lastPos = annotations_.lastOption match {
      case Some(a) => a.pos
      case None => rhs.pos
    }
    AssignmentStatement(lhs, rhs, annotations_)(getPos(lhs.pos, lastPos))
  }
  
  private def throwStatement(): ThrowStatement = {
    val t = accept(THROW)
    val varSymbol_ : VarSymbol = varSymbol()
    ThrowStatement(varSymbol_)( getPos(t.pos, varSymbol_.pos))
  }
  
  private def ifStatement(): IfStatement = {
    val i = accept(IF)
    val cond: BinaryExpression = binaryExpression()
    accept(THEN)
    accept(GOTO)
    val targetLocation: LocationSymbol = locationSymbol()
    IfStatement(cond, targetLocation)(getPos(i.pos, targetLocation.pos))
  }
  
  private def gotoStatement(): GotoStatement = {
    val goto = accept(GOTO)
    val targetLocation: LocationSymbol = locationSymbol()
    GotoStatement(targetLocation)(getPos(goto.pos, targetLocation.pos))
  }
  
  private def switchStatement(): SwitchStatement = {
    val s = accept(SWITCH)
    val condition: VarSymbol = varSymbol()
    val cases: IList[SwitchCase] = switchCases()
    val defaultCaseOpt: Option[SwitchDefaultCase] = switchDefaultCaseOpt()
    val lastPos = defaultCaseOpt match {
      case Some(d) => d.pos
      case None =>
        cases.lastOption match {
          case Some(c) => c.pos
          case None => condition.pos
        }
    }
    SwitchStatement(condition, cases, defaultCaseOpt)(getPos(s.pos, lastPos))
  }
  
  private def switchCases(): IList[SwitchCase] = {
    val cases: MList[SwitchCase] = mlistEmpty
    def loop(){
      val next = lookahead(1)
      if(next == INTEGER_LITERAL){
        currentTokenType match {
          case OP =>
            val bar: Token = accept(OP)
            if(bar.text != "|") throw new JawaParserException(currentToken.pos, "Expected op token " + "'|'" + " but got " + currentToken)
            val constant: Token = accept(INTEGER_LITERAL)
            accept(ARROW)
            accept(GOTO)
            val targetLocation: LocationSymbol = locationSymbol()
            cases += SwitchCase(constant, targetLocation)(getPos(bar.pos, targetLocation.pos))
            loop()
          case _ =>
        }
      }
    }
    loop()
    cases.toList
  }
  
  private def switchDefaultCaseOpt(): Option[SwitchDefaultCase] = {
    currentTokenType match {
      case OP =>
        if(currentToken.text == "|"){
          val bar = nextToken()
          accept(ELSE)
          accept(ARROW)
          accept(GOTO)
          val targetLocation: LocationSymbol = locationSymbol()
          Some(SwitchDefaultCase(targetLocation)(getPos(bar.pos, targetLocation.pos)))
        } else None
      case _ => None
    }
  }
  
  private def returnStatement(): ReturnStatement = {
    val r = accept(RETURN)
    var endPos: Position = r.pos
    val varOpt: Option[VarSymbol] =
      currentTokenType match {
        case ID =>
          val vs = varSymbol()
          endPos = vs.pos
          Some(vs)
        case _ => None
      }
    val annotations_ : IList[Annotation] = annotations()
    if(annotations_.nonEmpty) {
      endPos = annotations_.last.pos
    }
    ReturnStatement(varOpt, annotations_)(getPos(r.pos, endPos))
  }
  
  private def monitorStatement(): MonitorStatement = {
    val at = accept(AT)
    val monitor: Token = currentTokenType match {
      case MONITOR_ENTER => accept(MONITOR_ENTER)
      case MONITOR_EXIT => accept(MONITOR_EXIT)
      case _ => throw new JawaParserException(currentToken.pos, "Unexpected monitorStatement start: " + currentToken)
    }
    val varSymbol_ : VarSymbol = varSymbol()
    MonitorStatement(monitor, varSymbol_)(getPos(at.pos, varSymbol_.pos))
  }
  
  private def emptyStatement(): EmptyStatement = {
    val annotations_ : IList[Annotation] = annotations()
    val pos = if(annotations_.isEmpty) NoPosition
    else getPos(annotations_.head.pos, annotations_.last.pos)
    EmptyStatement(mlistEmpty ++ annotations_)(pos)
  }
  
  private def expression_lhs(): Expression with LHS = {
    currentTokenType match {
      case STATIC_ID =>
        staticFieldAccessExpression()
      case ID =>
        val next: TokenType = lookahead(1)
        next match {
          case DOT => accessExpression()
          case LBRACKET => indexingExpression()
          case _ => variableNameExpression()
        }
      case _ =>  throw new JawaParserException(currentToken.pos, "Unexpected expression_lhs start: " + currentToken)
    }
  }
  
  private def expression_rhs(): Expression with RHS = {
    currentTokenType match {
      case NEW => newExpression()
      case CMP => cmpExpression()
      case EXCEPTION => exceptionExpression()
      case CONST_CLASS => constClassExpression()
      case LENGTH => lengthExpression()
      case INSTANCE_OF => instanceofExpression()
      case NULL => nullExpression()
      case LPAREN => 
        val next: TokenType = lookahead(1)
        next match {
          case x if isLiteralToken(x) || x == RPAREN => tupleExpression()
          case _ => castExpression()
        }
      case _ if isLiteralToken(currentTokenType) => literalExpression()
      case _ if isUnaryOP(currentToken) => unaryExpression()
      case STATIC_ID =>
        staticFieldAccessExpression()
      case ID =>
        val next: TokenType = lookahead(1)
        next match {
          case DOT => accessExpression()
          case LBRACKET => indexingExpression()
          case OP => binaryExpression()
          case _ => variableNameExpression()
        }
      case _ => throw new JawaParserException(currentToken.pos, "Unexpected expression_rhs start: " + currentToken)
    }
  }
  
  private def nullExpression(): NullExpression = {
    val n = accept(NULL)
    NullExpression(n)(n.pos)
  }
  
  private def constClassExpression(): ConstClassExpression = {
    val cc = accept(CONST_CLASS)
    accept(AT)
    nextToken()
    val typExp: TypeExpression = typExpression()
    ConstClassExpression(typExp)(getPos(cc.pos, typExp.pos))
  }
  
  private def lengthExpression():LengthExpression = {
    val length = accept(LENGTH)
    accept(AT)
    nextToken()
    val varSymbol_ : VarSymbol = varSymbol()
    LengthExpression(varSymbol_)(getPos(length.pos, varSymbol_.pos))
  }
  
  private def instanceofExpression(): InstanceOfExpression = {
    val io = accept(INSTANCE_OF)
    accept(AT)
    nextToken()
    val varSymbol_ : VarSymbol = varSymbol()
    accept(AT)
    nextToken()
    val typExp : TypeExpression = typExpression()
    InstanceOfExpression(varSymbol_, typExp)(getPos(io.pos, typExp.pos))
  }
  
  private def exceptionExpression(): ExceptionExpression = {
    val exce = accept(EXCEPTION)
    accept(AT)
    nextToken()
    val typExp: TypeExpression = typExpression()
    ExceptionExpression(typExp)(getPos(exce.pos, typExp.pos))
  }

  private def variableNameExpression(): VariableNameExpression = {
    val varSymbol_ = varSymbol()
    VariableNameExpression(varSymbol_)(varSymbol_.pos)
  }

  private def staticFieldAccessExpression(): StaticFieldAccessExpression = {
    val sfns = staticFieldNameSymbol()
    accept(AT)
    nextToken()
    val typExp: TypeExpression = typExpression()
    StaticFieldAccessExpression(sfns, typExp)(getPos(sfns.pos, typExp.pos))
  }
  
  private def indexingExpression(): IndexingExpression = {
    val baseSymbol: VarSymbol = varSymbol()
    val indices: IList[IndexingSuffix] = indexingSuffixes()
    IndexingExpression(baseSymbol, indices)(getPos(baseSymbol.pos, indices.last.pos))
  }
  
  private def indexingSuffixes(): IList[IndexingSuffix] = {
    val indices: MList[IndexingSuffix] = mlistEmpty
    def loop(){
      currentTokenType match {
        case LBRACKET =>
          val lbracket = accept(LBRACKET)
          val index: Either[VarSymbol, LiteralExpression] = getVarOrLit
          val rbracket = accept(RBRACKET)
          indices += IndexingSuffix(index)(getPos(lbracket.pos, rbracket.pos))
          loop()
        case _ =>
      }
    }
    loop()
    indices.toList
  }
  
  private def accessExpression(): AccessExpression = {
    val baseSymbol: VarSymbol = varSymbol()
    accept(DOT)
    val fieldSym: FieldNameSymbol = fieldNameSymbol()
    accept(AT)
    nextToken()
    val typExp: TypeExpression = typExpression()
    AccessExpression(baseSymbol, fieldSym, typExp)(getPos(baseSymbol.pos, typExp.pos))
  }
  
  private def tupleExpression(): TupleExpression = {
    val lparen = accept(LPAREN)
    val constants: MList[LiteralExpression] = mlistEmpty
    while(currentTokenType != RPAREN) {
      if(!isLiteral) throw new JawaParserException(currentToken.pos, "expected literal but found " + currentToken)
      val cons: LiteralExpression = literalExpression()
      currentTokenType match {
        case COMMA => nextToken()
        case _ =>
      }
      constants += cons
    }
    val rparen = accept(RPAREN)
    TupleExpression(constants.toList)(getPos(lparen.pos, rparen.pos))
  }
  
  private def castExpression(): CastExpression = {
    val lparen = accept(LPAREN)
    val typ_ : Type = typ()
    accept(RPAREN)
    val varSym: VarSymbol = varSymbol()
    CastExpression(typ_, varSym)(getPos(lparen.pos, varSym.pos))
  }
  
  private def newExpression(): Expression with RHS with New = {
    val n = accept(NEW)
    val base: Type = typ()
    currentTokenType match {
      case LBRACKET =>
        accept(LBRACKET)
        val varSymbols: MList[VarSymbol] = mlistEmpty
        while(currentTokenType != RBRACKET) {
          val varSymbol_ : VarSymbol = varSymbol()
          currentTokenType match {
            case COMMA => nextToken()
            case _ =>
          }
          varSymbols += varSymbol_
        }
        val rbracket = accept(RBRACKET)
        NewArrayExpression(base, varSymbols.toList)(getPos(n.pos, rbracket.pos))
      case _ =>
        NewExpression(base)(getPos(n.pos, base.pos))
    }
  }
  
  private def literalExpression(): LiteralExpression = {
    if(!isLiteral) throw new JawaParserException(currentToken.pos, "expected literal but found " + currentToken)
    val constant: Token = nextToken()
    LiteralExpression(constant)(constant.pos)
  }

  private def getVarOrLitOrNull: Either[VarSymbol, Either[LiteralExpression,NullExpression]] = {
    currentTokenType match {
      case x if isLiteralToken(x) =>
        if(x == NULL) {
          Right(Right(nullExpression()))
        } else Right(Left(literalExpression()))
      case _ => Left(varSymbol())
    }
  }
  
  private def getVarOrLit: Either[VarSymbol, LiteralExpression] = {
    currentTokenType match {
      case x if isLiteralToken(x) => Right(literalExpression())
      case _ => Left(varSymbol())
    }
  }
  
  private def unaryExpression(): UnaryExpression = {
    val op: Token = accept(OP) // need to check is it unary op
    val unary: VarSymbol = varSymbol()
    UnaryExpression(op, unary)(getPos(op.pos, unary.pos))
  }
  
  private def binaryExpression(): BinaryExpression = {
    if(currentTokenType != ID && 
       currentTokenType != INTEGER_LITERAL &&
       currentTokenType != FLOATING_POINT_LITERAL)
      throw new JawaParserException(currentToken.pos, "expected 'ID' or 'INTEGER_LITERAL' or 'FLOATING_POINT_LITERAL' but " + currentToken + " found")
    val left: VarSymbol = varSymbol()
    val op: Token = accept(OP) // need to check is it binary op
    if(currentTokenType != ID && 
       currentTokenType != INTEGER_LITERAL &&
       currentTokenType != FLOATING_POINT_LITERAL &&
       currentTokenType != NULL)
      throw new JawaParserException(currentToken.pos, "expected 'ID' or 'INTEGER_LITERAL' or 'FLOATING_POINT_LITERAL' or 'NULL' but " + currentToken + " found")
    val right: Either[VarSymbol, Either[LiteralExpression, NullExpression]] = getVarOrLitOrNull
    val lastPos = right match {
      case Left(v) => v.pos
      case Right(Left(l)) => l.pos
      case Right(Right(n)) => n.pos
    }
    BinaryExpression(left, op, right)(getPos(left.pos, lastPos))
  }
  
  private def catchClauses(): IList[CatchClause] = {
    val catchClauses: MList[CatchClause] = mlistEmpty
    def loop() {
      currentTokenType match {
        case CATCH =>
          catchClauses += catchClause()
          loop()
        case _ =>
      }
    }
    loop()
    catchClauses.toList
  }
  
  private def cmpExpression(): CmpExpression = {
    val cmp = accept(CMP)
    accept(LPAREN)
    val var1Symbol: VarSymbol = varSymbol()
    accept(COMMA)
    val var2Symbol: VarSymbol = varSymbol()
    val rparen = accept(RPAREN)
    CmpExpression(cmp, var1Symbol, var2Symbol)(getPos(cmp.pos, rparen.pos))
  }
  
  private def catchClause(): CatchClause = {
    val ca = accept(CATCH)
    val typ_ : Type = typ()
    val range: CatchRange = catchRange()
    accept(GOTO)
    val targetLocation: LocationSymbol = locationSymbol()
    val semi = accept(SEMI)
    CatchClause(typ_, range, targetLocation)(getPos(ca.pos, semi.pos))
  }
  
  private def catchRange(): CatchRange = {
    val at = accept(AT)
    accept(LBRACKET)
    val fromLocation: LocationSymbol = locationSymbol()
    accept(RANGE)
    val toLocation: LocationSymbol = locationSymbol()
    val rbracket = accept(RBRACKET)
    CatchRange(fromLocation, toLocation)(getPos(at.pos, rbracket.pos))
  }
  
  private def typExpression(): TypeExpression = {
    val hat = accept(HAT)
    val typ_ : Type = typ()
    TypeExpression(typ_)(getPos(hat.pos, typ_.pos))
  }
  
  private def typ(): Type = {
    val baseTypeSymbol: TypeSymbol = typeSymbol()
    val typeFragments: MList[TypeFragment] = mlistEmpty
    def loop() {
      currentTokenType match {
        case LBRACKET =>
          val next: TokenType = lookahead(1)
          next match {
            case RBRACKET =>
              val tf = typeFragment()
              typeFragments += tf
              loop()
            case _ =>
          }
        case _ =>
      }
    }
    loop()
    val lastPos = typeFragments.lastOption match {
      case Some(t) => t.pos
      case None => baseTypeSymbol.pos
    }
    Type(baseTypeSymbol, typeFragments.toList)(getPos(baseTypeSymbol.pos, lastPos))
  }
  
  private def typeFragment(): TypeFragment = {
    val lbracket = accept(LBRACKET)
    val rbracket = accept(RBRACKET)
    TypeFragment()(getPos(lbracket.pos, rbracket.pos))
  }
  
  private def isUnaryOP(token: Token): Boolean = {
    val text = token.text
    text match {
      case "+" | "-" | "/" | "%" | "*" | "!" | "~" => true
      case _ => false
    }
  }
  
  private def isLiteralToken(tokenType: TokenType): Boolean = LITERALS.contains(tokenType)

  private def isLiteral = isLiteralToken(currentTokenType)
  
  private def accept(tokenType: TokenType): Token = if (currentTokenType == tokenType) {
    nextToken()
  } else {
    throw new JawaParserException(currentToken.pos, "Expected token " + tokenType + " but got " + currentToken)
  }

  private val tokensArray: Array[Token] = tokens

  private var pos = 0

  private def currentToken: Token = this(pos)

  private def apply(pos: Int): Token =
    if (pos < tokensArray.length)
      tokensArray(pos)
    else
      tokens.last

  private def currentTokenType = currentToken.tokenType

  /** @return the token before advancing */
  private def nextToken(): Token = {
    val token = currentToken
    pos += 1
    if(logging) {
      println("nextToken(): " + token + " --> " + currentToken)
    }
    token
  }

  private def lookahead(n: Int): TokenType = this(pos + n).tokenType
}

object JawaParser {
  /**
   * parse the given source as a parsable ast node
   */
  def parse[T <: ParsableAstNode](source: Either[String, SourceFile], resolveBody: Boolean, reporter: Reporter, claz: Class[T]): Try[T] = {
      val tokens = JawaLexer.tokenise(source, reporter)
      parse(tokens, resolveBody, reporter, claz)
  }
  
  def parse[T <: ParsableAstNode](tokens: IList[Token], resolveBody: Boolean, reporter: Reporter, clazz: Class[T]): Try[T] = {
    val parser = new JawaParser(tokens.toArray, reporter)
    try{
      val pasable = clazz.getName match {
        case "org.argus.jawa.core.ast.CompilationUnit" =>
          parser.compilationUnit(resolveBody)
        case "org.argus.jawa.core.ast.ClassOrInterfaceDeclaration" =>
          parser.classOrInterfaceDeclaration(resolveBody)
        case "org.argus.jawa.core.ast.MethodDeclaration" =>
          parser.methodDeclaration(resolveBody)
        case "org.argus.jawa.core.ast.Body" =>
          parser.body(resolveBody)
        case "org.argus.jawa.core.ast.Location" =>
          parser.location
        case a =>
          throw new JawaParserException(NoPosition, s"Cannot parse type $a")
      }
      Success(pasable.asInstanceOf[T])
    } catch {
      case e: JawaParserException =>
        reporter.error(e.pos, e.message)
        Failure(e)
    }
  }
}
