// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.jawa/src/main/java/org/argus/jawa/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.jawa.summary.grammar;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast"})
public class SafsuParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.7", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		T__0=1, T__1=2, T__2=3, T__3=4, T__4=5, T__5=6, T__6=7, T__7=8, T__8=9, 
		T__9=10, T__10=11, T__11=12, T__12=13, T__13=14, T__14=15, T__15=16, T__16=17, 
		UID=18, ID=19, Digits=20, STRING=21, MSTRING=22, WS=23, COMMENT=24, LINE_COMMENT=25;
	public static final int
		RULE_summaryFile = 0, RULE_defaultType = 1, RULE_summary = 2, RULE_signature = 3, 
		RULE_suRule = 4, RULE_clearRule = 5, RULE_binaryRule = 6, RULE_ops = 7, 
		RULE_lhs = 8, RULE_rhs = 9, RULE_suThis = 10, RULE_arg = 11, RULE_global = 12, 
		RULE_heap = 13, RULE_heapAccess = 14, RULE_fieldAccess = 15, RULE_arrayAccess = 16, 
		RULE_mapAccess = 17, RULE_instance = 18, RULE_classOf = 19, RULE_type = 20, 
		RULE_javaType = 21, RULE_innerType = 22, RULE_unknown = 23, RULE_stringLit = 24, 
		RULE_ret = 25, RULE_location = 26, RULE_virtualLocation = 27, RULE_concreteLocation = 28;
	public static final String[] ruleNames = {
		"summaryFile", "defaultType", "summary", "signature", "suRule", "clearRule", 
		"binaryRule", "ops", "lhs", "rhs", "suThis", "arg", "global", "heap", 
		"heapAccess", "fieldAccess", "arrayAccess", "mapAccess", "instance", "classOf", 
		"type", "javaType", "innerType", "unknown", "stringLit", "ret", "location", 
		"virtualLocation", "concreteLocation"
	};

	private static final String[] _LITERAL_NAMES = {
		null, "':'", "';'", "'~'", "'='", "'+='", "'-='", "'this'", "'arg'", "'.'", 
		"'[]'", "'('", "')'", "'@'", "'classOf'", "'$'", "'?'", "'ret'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, null, null, null, null, null, null, null, null, null, null, null, 
		null, null, null, null, null, null, "UID", "ID", "Digits", "STRING", "MSTRING", 
		"WS", "COMMENT", "LINE_COMMENT"
	};
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "Safsu.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public SafsuParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}
	public static class SummaryFileContext extends ParserRuleContext {
		public TerminalNode EOF() { return getToken(SafsuParser.EOF, 0); }
		public List<DefaultTypeContext> defaultType() {
			return getRuleContexts(DefaultTypeContext.class);
		}
		public DefaultTypeContext defaultType(int i) {
			return getRuleContext(DefaultTypeContext.class,i);
		}
		public List<SummaryContext> summary() {
			return getRuleContexts(SummaryContext.class);
		}
		public SummaryContext summary(int i) {
			return getRuleContext(SummaryContext.class,i);
		}
		public SummaryFileContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_summaryFile; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterSummaryFile(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitSummaryFile(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitSummaryFile(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SummaryFileContext summaryFile() throws RecognitionException {
		SummaryFileContext _localctx = new SummaryFileContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_summaryFile);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(61);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==ID) {
				{
				{
				setState(58);
				defaultType();
				}
				}
				setState(63);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(67);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==UID) {
				{
				{
				setState(64);
				summary();
				}
				}
				setState(69);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(70);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DefaultTypeContext extends ParserRuleContext {
		public List<JavaTypeContext> javaType() {
			return getRuleContexts(JavaTypeContext.class);
		}
		public JavaTypeContext javaType(int i) {
			return getRuleContext(JavaTypeContext.class,i);
		}
		public TerminalNode ID() { return getToken(SafsuParser.ID, 0); }
		public DefaultTypeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_defaultType; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterDefaultType(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitDefaultType(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitDefaultType(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DefaultTypeContext defaultType() throws RecognitionException {
		DefaultTypeContext _localctx = new DefaultTypeContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_defaultType);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(72);
			javaType();
			setState(73);
			match(T__0);
			setState(74);
			match(ID);
			setState(75);
			match(T__0);
			setState(76);
			javaType();
			setState(77);
			match(T__1);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SummaryContext extends ParserRuleContext {
		public SignatureContext signature() {
			return getRuleContext(SignatureContext.class,0);
		}
		public List<SuRuleContext> suRule() {
			return getRuleContexts(SuRuleContext.class);
		}
		public SuRuleContext suRule(int i) {
			return getRuleContext(SuRuleContext.class,i);
		}
		public SummaryContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_summary; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterSummary(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitSummary(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitSummary(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SummaryContext summary() throws RecognitionException {
		SummaryContext _localctx = new SummaryContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_summary);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(79);
			signature();
			setState(80);
			match(T__0);
			setState(84);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__2) | (1L << T__6) | (1L << T__7) | (1L << T__16) | (1L << UID))) != 0)) {
				{
				{
				setState(81);
				suRule();
				}
				}
				setState(86);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(87);
			match(T__1);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SignatureContext extends ParserRuleContext {
		public TerminalNode UID() { return getToken(SafsuParser.UID, 0); }
		public SignatureContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_signature; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterSignature(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitSignature(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitSignature(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SignatureContext signature() throws RecognitionException {
		SignatureContext _localctx = new SignatureContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_signature);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(89);
			match(UID);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SuRuleContext extends ParserRuleContext {
		public ClearRuleContext clearRule() {
			return getRuleContext(ClearRuleContext.class,0);
		}
		public BinaryRuleContext binaryRule() {
			return getRuleContext(BinaryRuleContext.class,0);
		}
		public SuRuleContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_suRule; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterSuRule(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitSuRule(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitSuRule(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SuRuleContext suRule() throws RecognitionException {
		SuRuleContext _localctx = new SuRuleContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_suRule);
		try {
			setState(93);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__2:
				enterOuterAlt(_localctx, 1);
				{
				setState(91);
				clearRule();
				}
				break;
			case T__6:
			case T__7:
			case T__16:
			case UID:
				enterOuterAlt(_localctx, 2);
				{
				setState(92);
				binaryRule();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ClearRuleContext extends ParserRuleContext {
		public SuThisContext suThis() {
			return getRuleContext(SuThisContext.class,0);
		}
		public ArgContext arg() {
			return getRuleContext(ArgContext.class,0);
		}
		public GlobalContext global() {
			return getRuleContext(GlobalContext.class,0);
		}
		public ClearRuleContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_clearRule; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterClearRule(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitClearRule(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitClearRule(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ClearRuleContext clearRule() throws RecognitionException {
		ClearRuleContext _localctx = new ClearRuleContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_clearRule);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(95);
			match(T__2);
			setState(99);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				{
				setState(96);
				suThis();
				}
				break;
			case T__7:
				{
				setState(97);
				arg();
				}
				break;
			case UID:
				{
				setState(98);
				global();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class BinaryRuleContext extends ParserRuleContext {
		public LhsContext lhs() {
			return getRuleContext(LhsContext.class,0);
		}
		public OpsContext ops() {
			return getRuleContext(OpsContext.class,0);
		}
		public RhsContext rhs() {
			return getRuleContext(RhsContext.class,0);
		}
		public BinaryRuleContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_binaryRule; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterBinaryRule(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitBinaryRule(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitBinaryRule(this);
			else return visitor.visitChildren(this);
		}
	}

	public final BinaryRuleContext binaryRule() throws RecognitionException {
		BinaryRuleContext _localctx = new BinaryRuleContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_binaryRule);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(101);
			lhs();
			setState(102);
			ops();
			setState(103);
			rhs();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class OpsContext extends ParserRuleContext {
		public OpsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_ops; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterOps(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitOps(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitOps(this);
			else return visitor.visitChildren(this);
		}
	}

	public final OpsContext ops() throws RecognitionException {
		OpsContext _localctx = new OpsContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_ops);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(105);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__3) | (1L << T__4) | (1L << T__5))) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LhsContext extends ParserRuleContext {
		public SuThisContext suThis() {
			return getRuleContext(SuThisContext.class,0);
		}
		public ArgContext arg() {
			return getRuleContext(ArgContext.class,0);
		}
		public GlobalContext global() {
			return getRuleContext(GlobalContext.class,0);
		}
		public RetContext ret() {
			return getRuleContext(RetContext.class,0);
		}
		public LhsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_lhs; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterLhs(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitLhs(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitLhs(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LhsContext lhs() throws RecognitionException {
		LhsContext _localctx = new LhsContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_lhs);
		try {
			setState(111);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				enterOuterAlt(_localctx, 1);
				{
				setState(107);
				suThis();
				}
				break;
			case T__7:
				enterOuterAlt(_localctx, 2);
				{
				setState(108);
				arg();
				}
				break;
			case UID:
				enterOuterAlt(_localctx, 3);
				{
				setState(109);
				global();
				}
				break;
			case T__16:
				enterOuterAlt(_localctx, 4);
				{
				setState(110);
				ret();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class RhsContext extends ParserRuleContext {
		public SuThisContext suThis() {
			return getRuleContext(SuThisContext.class,0);
		}
		public ArgContext arg() {
			return getRuleContext(ArgContext.class,0);
		}
		public GlobalContext global() {
			return getRuleContext(GlobalContext.class,0);
		}
		public InstanceContext instance() {
			return getRuleContext(InstanceContext.class,0);
		}
		public ClassOfContext classOf() {
			return getRuleContext(ClassOfContext.class,0);
		}
		public RhsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_rhs; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterRhs(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitRhs(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitRhs(this);
			else return visitor.visitChildren(this);
		}
	}

	public final RhsContext rhs() throws RecognitionException {
		RhsContext _localctx = new RhsContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_rhs);
		try {
			setState(118);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				enterOuterAlt(_localctx, 1);
				{
				setState(113);
				suThis();
				}
				break;
			case T__7:
				enterOuterAlt(_localctx, 2);
				{
				setState(114);
				arg();
				}
				break;
			case UID:
				enterOuterAlt(_localctx, 3);
				{
				setState(115);
				global();
				}
				break;
			case ID:
			case STRING:
			case MSTRING:
				enterOuterAlt(_localctx, 4);
				{
				setState(116);
				instance();
				}
				break;
			case T__13:
				enterOuterAlt(_localctx, 5);
				{
				setState(117);
				classOf();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class SuThisContext extends ParserRuleContext {
		public HeapContext heap() {
			return getRuleContext(HeapContext.class,0);
		}
		public SuThisContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_suThis; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterSuThis(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitSuThis(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitSuThis(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SuThisContext suThis() throws RecognitionException {
		SuThisContext _localctx = new SuThisContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_suThis);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(120);
			match(T__6);
			setState(122);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__8) | (1L << T__9) | (1L << T__10))) != 0)) {
				{
				setState(121);
				heap();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArgContext extends ParserRuleContext {
		public TerminalNode Digits() { return getToken(SafsuParser.Digits, 0); }
		public HeapContext heap() {
			return getRuleContext(HeapContext.class,0);
		}
		public ArgContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arg; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterArg(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitArg(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitArg(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArgContext arg() throws RecognitionException {
		ArgContext _localctx = new ArgContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_arg);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(124);
			match(T__7);
			setState(125);
			match(T__0);
			setState(126);
			match(Digits);
			setState(128);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__8) | (1L << T__9) | (1L << T__10))) != 0)) {
				{
				setState(127);
				heap();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class GlobalContext extends ParserRuleContext {
		public TerminalNode UID() { return getToken(SafsuParser.UID, 0); }
		public HeapContext heap() {
			return getRuleContext(HeapContext.class,0);
		}
		public GlobalContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_global; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterGlobal(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitGlobal(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitGlobal(this);
			else return visitor.visitChildren(this);
		}
	}

	public final GlobalContext global() throws RecognitionException {
		GlobalContext _localctx = new GlobalContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_global);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(130);
			match(UID);
			setState(132);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__8) | (1L << T__9) | (1L << T__10))) != 0)) {
				{
				setState(131);
				heap();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class HeapContext extends ParserRuleContext {
		public List<HeapAccessContext> heapAccess() {
			return getRuleContexts(HeapAccessContext.class);
		}
		public HeapAccessContext heapAccess(int i) {
			return getRuleContext(HeapAccessContext.class,i);
		}
		public HeapContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_heap; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterHeap(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitHeap(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitHeap(this);
			else return visitor.visitChildren(this);
		}
	}

	public final HeapContext heap() throws RecognitionException {
		HeapContext _localctx = new HeapContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_heap);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(135); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(134);
				heapAccess();
				}
				}
				setState(137); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__8) | (1L << T__9) | (1L << T__10))) != 0) );
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class HeapAccessContext extends ParserRuleContext {
		public FieldAccessContext fieldAccess() {
			return getRuleContext(FieldAccessContext.class,0);
		}
		public ArrayAccessContext arrayAccess() {
			return getRuleContext(ArrayAccessContext.class,0);
		}
		public MapAccessContext mapAccess() {
			return getRuleContext(MapAccessContext.class,0);
		}
		public HeapAccessContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_heapAccess; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterHeapAccess(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitHeapAccess(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitHeapAccess(this);
			else return visitor.visitChildren(this);
		}
	}

	public final HeapAccessContext heapAccess() throws RecognitionException {
		HeapAccessContext _localctx = new HeapAccessContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_heapAccess);
		try {
			setState(142);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__8:
				enterOuterAlt(_localctx, 1);
				{
				setState(139);
				fieldAccess();
				}
				break;
			case T__9:
				enterOuterAlt(_localctx, 2);
				{
				setState(140);
				arrayAccess();
				}
				break;
			case T__10:
				enterOuterAlt(_localctx, 3);
				{
				setState(141);
				mapAccess();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FieldAccessContext extends ParserRuleContext {
		public TerminalNode ID() { return getToken(SafsuParser.ID, 0); }
		public FieldAccessContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_fieldAccess; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterFieldAccess(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitFieldAccess(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitFieldAccess(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FieldAccessContext fieldAccess() throws RecognitionException {
		FieldAccessContext _localctx = new FieldAccessContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_fieldAccess);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(144);
			match(T__8);
			setState(145);
			match(ID);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ArrayAccessContext extends ParserRuleContext {
		public ArrayAccessContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrayAccess; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterArrayAccess(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitArrayAccess(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitArrayAccess(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrayAccessContext arrayAccess() throws RecognitionException {
		ArrayAccessContext _localctx = new ArrayAccessContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_arrayAccess);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(147);
			match(T__9);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MapAccessContext extends ParserRuleContext {
		public RhsContext rhs() {
			return getRuleContext(RhsContext.class,0);
		}
		public MapAccessContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_mapAccess; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterMapAccess(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitMapAccess(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitMapAccess(this);
			else return visitor.visitChildren(this);
		}
	}

	public final MapAccessContext mapAccess() throws RecognitionException {
		MapAccessContext _localctx = new MapAccessContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_mapAccess);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(149);
			match(T__10);
			setState(151);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__6) | (1L << T__7) | (1L << T__13) | (1L << UID) | (1L << ID) | (1L << STRING) | (1L << MSTRING))) != 0)) {
				{
				setState(150);
				rhs();
				}
			}

			setState(153);
			match(T__11);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class InstanceContext extends ParserRuleContext {
		public TypeContext type() {
			return getRuleContext(TypeContext.class,0);
		}
		public LocationContext location() {
			return getRuleContext(LocationContext.class,0);
		}
		public InstanceContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_instance; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterInstance(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitInstance(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitInstance(this);
			else return visitor.visitChildren(this);
		}
	}

	public final InstanceContext instance() throws RecognitionException {
		InstanceContext _localctx = new InstanceContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_instance);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(155);
			type();
			setState(156);
			match(T__12);
			setState(157);
			location();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ClassOfContext extends ParserRuleContext {
		public RhsContext rhs() {
			return getRuleContext(RhsContext.class,0);
		}
		public LocationContext location() {
			return getRuleContext(LocationContext.class,0);
		}
		public ClassOfContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_classOf; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterClassOf(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitClassOf(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitClassOf(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ClassOfContext classOf() throws RecognitionException {
		ClassOfContext _localctx = new ClassOfContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_classOf);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(159);
			match(T__13);
			setState(160);
			rhs();
			setState(161);
			match(T__12);
			setState(162);
			location();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class TypeContext extends ParserRuleContext {
		public JavaTypeContext javaType() {
			return getRuleContext(JavaTypeContext.class,0);
		}
		public StringLitContext stringLit() {
			return getRuleContext(StringLitContext.class,0);
		}
		public TypeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_type; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterType(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitType(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitType(this);
			else return visitor.visitChildren(this);
		}
	}

	public final TypeContext type() throws RecognitionException {
		TypeContext _localctx = new TypeContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_type);
		try {
			setState(166);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case ID:
				enterOuterAlt(_localctx, 1);
				{
				setState(164);
				javaType();
				}
				break;
			case STRING:
			case MSTRING:
				enterOuterAlt(_localctx, 2);
				{
				setState(165);
				stringLit();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class JavaTypeContext extends ParserRuleContext {
		public List<TerminalNode> ID() { return getTokens(SafsuParser.ID); }
		public TerminalNode ID(int i) {
			return getToken(SafsuParser.ID, i);
		}
		public List<InnerTypeContext> innerType() {
			return getRuleContexts(InnerTypeContext.class);
		}
		public InnerTypeContext innerType(int i) {
			return getRuleContext(InnerTypeContext.class,i);
		}
		public UnknownContext unknown() {
			return getRuleContext(UnknownContext.class,0);
		}
		public List<ArrayAccessContext> arrayAccess() {
			return getRuleContexts(ArrayAccessContext.class);
		}
		public ArrayAccessContext arrayAccess(int i) {
			return getRuleContext(ArrayAccessContext.class,i);
		}
		public JavaTypeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_javaType; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterJavaType(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitJavaType(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitJavaType(this);
			else return visitor.visitChildren(this);
		}
	}

	public final JavaTypeContext javaType() throws RecognitionException {
		JavaTypeContext _localctx = new JavaTypeContext(_ctx, getState());
		enterRule(_localctx, 42, RULE_javaType);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(168);
			match(ID);
			setState(173);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__8) {
				{
				{
				setState(169);
				match(T__8);
				setState(170);
				match(ID);
				}
				}
				setState(175);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(179);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__14) {
				{
				{
				setState(176);
				innerType();
				}
				}
				setState(181);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(183);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__15) {
				{
				setState(182);
				unknown();
				}
			}

			setState(188);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__9) {
				{
				{
				setState(185);
				arrayAccess();
				}
				}
				setState(190);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class InnerTypeContext extends ParserRuleContext {
		public TerminalNode ID() { return getToken(SafsuParser.ID, 0); }
		public InnerTypeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_innerType; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterInnerType(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitInnerType(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitInnerType(this);
			else return visitor.visitChildren(this);
		}
	}

	public final InnerTypeContext innerType() throws RecognitionException {
		InnerTypeContext _localctx = new InnerTypeContext(_ctx, getState());
		enterRule(_localctx, 44, RULE_innerType);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(191);
			match(T__14);
			setState(192);
			match(ID);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class UnknownContext extends ParserRuleContext {
		public UnknownContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_unknown; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterUnknown(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitUnknown(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitUnknown(this);
			else return visitor.visitChildren(this);
		}
	}

	public final UnknownContext unknown() throws RecognitionException {
		UnknownContext _localctx = new UnknownContext(_ctx, getState());
		enterRule(_localctx, 46, RULE_unknown);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(194);
			match(T__15);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class StringLitContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(SafsuParser.STRING, 0); }
		public TerminalNode MSTRING() { return getToken(SafsuParser.MSTRING, 0); }
		public StringLitContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_stringLit; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterStringLit(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitStringLit(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitStringLit(this);
			else return visitor.visitChildren(this);
		}
	}

	public final StringLitContext stringLit() throws RecognitionException {
		StringLitContext _localctx = new StringLitContext(_ctx, getState());
		enterRule(_localctx, 48, RULE_stringLit);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(196);
			_la = _input.LA(1);
			if ( !(_la==STRING || _la==MSTRING) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class RetContext extends ParserRuleContext {
		public HeapContext heap() {
			return getRuleContext(HeapContext.class,0);
		}
		public RetContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_ret; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterRet(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitRet(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitRet(this);
			else return visitor.visitChildren(this);
		}
	}

	public final RetContext ret() throws RecognitionException {
		RetContext _localctx = new RetContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_ret);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(198);
			match(T__16);
			setState(200);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__8) | (1L << T__9) | (1L << T__10))) != 0)) {
				{
				setState(199);
				heap();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class LocationContext extends ParserRuleContext {
		public VirtualLocationContext virtualLocation() {
			return getRuleContext(VirtualLocationContext.class,0);
		}
		public ConcreteLocationContext concreteLocation() {
			return getRuleContext(ConcreteLocationContext.class,0);
		}
		public LocationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_location; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterLocation(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitLocation(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitLocation(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LocationContext location() throws RecognitionException {
		LocationContext _localctx = new LocationContext(_ctx, getState());
		enterRule(_localctx, 52, RULE_location);
		try {
			setState(204);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__2:
				enterOuterAlt(_localctx, 1);
				{
				setState(202);
				virtualLocation();
				}
				break;
			case ID:
				enterOuterAlt(_localctx, 2);
				{
				setState(203);
				concreteLocation();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class VirtualLocationContext extends ParserRuleContext {
		public VirtualLocationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_virtualLocation; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterVirtualLocation(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitVirtualLocation(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitVirtualLocation(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VirtualLocationContext virtualLocation() throws RecognitionException {
		VirtualLocationContext _localctx = new VirtualLocationContext(_ctx, getState());
		enterRule(_localctx, 54, RULE_virtualLocation);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(206);
			match(T__2);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ConcreteLocationContext extends ParserRuleContext {
		public TerminalNode ID() { return getToken(SafsuParser.ID, 0); }
		public ConcreteLocationContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_concreteLocation; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).enterConcreteLocation(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof SafsuListener ) ((SafsuListener)listener).exitConcreteLocation(this);
		}
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof SafsuVisitor ) return ((SafsuVisitor<? extends T>)visitor).visitConcreteLocation(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ConcreteLocationContext concreteLocation() throws RecognitionException {
		ConcreteLocationContext _localctx = new ConcreteLocationContext(_ctx, getState());
		enterRule(_localctx, 56, RULE_concreteLocation);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(208);
			match(ID);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static final String _serializedATN =
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3\33\u00d5\4\2\t\2"+
		"\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13"+
		"\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22"+
		"\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31\t\31"+
		"\4\32\t\32\4\33\t\33\4\34\t\34\4\35\t\35\4\36\t\36\3\2\7\2>\n\2\f\2\16"+
		"\2A\13\2\3\2\7\2D\n\2\f\2\16\2G\13\2\3\2\3\2\3\3\3\3\3\3\3\3\3\3\3\3\3"+
		"\3\3\4\3\4\3\4\7\4U\n\4\f\4\16\4X\13\4\3\4\3\4\3\5\3\5\3\6\3\6\5\6`\n"+
		"\6\3\7\3\7\3\7\3\7\5\7f\n\7\3\b\3\b\3\b\3\b\3\t\3\t\3\n\3\n\3\n\3\n\5"+
		"\nr\n\n\3\13\3\13\3\13\3\13\3\13\5\13y\n\13\3\f\3\f\5\f}\n\f\3\r\3\r\3"+
		"\r\3\r\5\r\u0083\n\r\3\16\3\16\5\16\u0087\n\16\3\17\6\17\u008a\n\17\r"+
		"\17\16\17\u008b\3\20\3\20\3\20\5\20\u0091\n\20\3\21\3\21\3\21\3\22\3\22"+
		"\3\23\3\23\5\23\u009a\n\23\3\23\3\23\3\24\3\24\3\24\3\24\3\25\3\25\3\25"+
		"\3\25\3\25\3\26\3\26\5\26\u00a9\n\26\3\27\3\27\3\27\7\27\u00ae\n\27\f"+
		"\27\16\27\u00b1\13\27\3\27\7\27\u00b4\n\27\f\27\16\27\u00b7\13\27\3\27"+
		"\5\27\u00ba\n\27\3\27\7\27\u00bd\n\27\f\27\16\27\u00c0\13\27\3\30\3\30"+
		"\3\30\3\31\3\31\3\32\3\32\3\33\3\33\5\33\u00cb\n\33\3\34\3\34\5\34\u00cf"+
		"\n\34\3\35\3\35\3\36\3\36\3\36\2\2\37\2\4\6\b\n\f\16\20\22\24\26\30\32"+
		"\34\36 \"$&(*,.\60\62\64\668:\2\4\3\2\6\b\3\2\27\30\2\u00d2\2?\3\2\2\2"+
		"\4J\3\2\2\2\6Q\3\2\2\2\b[\3\2\2\2\n_\3\2\2\2\fa\3\2\2\2\16g\3\2\2\2\20"+
		"k\3\2\2\2\22q\3\2\2\2\24x\3\2\2\2\26z\3\2\2\2\30~\3\2\2\2\32\u0084\3\2"+
		"\2\2\34\u0089\3\2\2\2\36\u0090\3\2\2\2 \u0092\3\2\2\2\"\u0095\3\2\2\2"+
		"$\u0097\3\2\2\2&\u009d\3\2\2\2(\u00a1\3\2\2\2*\u00a8\3\2\2\2,\u00aa\3"+
		"\2\2\2.\u00c1\3\2\2\2\60\u00c4\3\2\2\2\62\u00c6\3\2\2\2\64\u00c8\3\2\2"+
		"\2\66\u00ce\3\2\2\28\u00d0\3\2\2\2:\u00d2\3\2\2\2<>\5\4\3\2=<\3\2\2\2"+
		">A\3\2\2\2?=\3\2\2\2?@\3\2\2\2@E\3\2\2\2A?\3\2\2\2BD\5\6\4\2CB\3\2\2\2"+
		"DG\3\2\2\2EC\3\2\2\2EF\3\2\2\2FH\3\2\2\2GE\3\2\2\2HI\7\2\2\3I\3\3\2\2"+
		"\2JK\5,\27\2KL\7\3\2\2LM\7\25\2\2MN\7\3\2\2NO\5,\27\2OP\7\4\2\2P\5\3\2"+
		"\2\2QR\5\b\5\2RV\7\3\2\2SU\5\n\6\2TS\3\2\2\2UX\3\2\2\2VT\3\2\2\2VW\3\2"+
		"\2\2WY\3\2\2\2XV\3\2\2\2YZ\7\4\2\2Z\7\3\2\2\2[\\\7\24\2\2\\\t\3\2\2\2"+
		"]`\5\f\7\2^`\5\16\b\2_]\3\2\2\2_^\3\2\2\2`\13\3\2\2\2ae\7\5\2\2bf\5\26"+
		"\f\2cf\5\30\r\2df\5\32\16\2eb\3\2\2\2ec\3\2\2\2ed\3\2\2\2f\r\3\2\2\2g"+
		"h\5\22\n\2hi\5\20\t\2ij\5\24\13\2j\17\3\2\2\2kl\t\2\2\2l\21\3\2\2\2mr"+
		"\5\26\f\2nr\5\30\r\2or\5\32\16\2pr\5\64\33\2qm\3\2\2\2qn\3\2\2\2qo\3\2"+
		"\2\2qp\3\2\2\2r\23\3\2\2\2sy\5\26\f\2ty\5\30\r\2uy\5\32\16\2vy\5&\24\2"+
		"wy\5(\25\2xs\3\2\2\2xt\3\2\2\2xu\3\2\2\2xv\3\2\2\2xw\3\2\2\2y\25\3\2\2"+
		"\2z|\7\t\2\2{}\5\34\17\2|{\3\2\2\2|}\3\2\2\2}\27\3\2\2\2~\177\7\n\2\2"+
		"\177\u0080\7\3\2\2\u0080\u0082\7\26\2\2\u0081\u0083\5\34\17\2\u0082\u0081"+
		"\3\2\2\2\u0082\u0083\3\2\2\2\u0083\31\3\2\2\2\u0084\u0086\7\24\2\2\u0085"+
		"\u0087\5\34\17\2\u0086\u0085\3\2\2\2\u0086\u0087\3\2\2\2\u0087\33\3\2"+
		"\2\2\u0088\u008a\5\36\20\2\u0089\u0088\3\2\2\2\u008a\u008b\3\2\2\2\u008b"+
		"\u0089\3\2\2\2\u008b\u008c\3\2\2\2\u008c\35\3\2\2\2\u008d\u0091\5 \21"+
		"\2\u008e\u0091\5\"\22\2\u008f\u0091\5$\23\2\u0090\u008d\3\2\2\2\u0090"+
		"\u008e\3\2\2\2\u0090\u008f\3\2\2\2\u0091\37\3\2\2\2\u0092\u0093\7\13\2"+
		"\2\u0093\u0094\7\25\2\2\u0094!\3\2\2\2\u0095\u0096\7\f\2\2\u0096#\3\2"+
		"\2\2\u0097\u0099\7\r\2\2\u0098\u009a\5\24\13\2\u0099\u0098\3\2\2\2\u0099"+
		"\u009a\3\2\2\2\u009a\u009b\3\2\2\2\u009b\u009c\7\16\2\2\u009c%\3\2\2\2"+
		"\u009d\u009e\5*\26\2\u009e\u009f\7\17\2\2\u009f\u00a0\5\66\34\2\u00a0"+
		"\'\3\2\2\2\u00a1\u00a2\7\20\2\2\u00a2\u00a3\5\24\13\2\u00a3\u00a4\7\17"+
		"\2\2\u00a4\u00a5\5\66\34\2\u00a5)\3\2\2\2\u00a6\u00a9\5,\27\2\u00a7\u00a9"+
		"\5\62\32\2\u00a8\u00a6\3\2\2\2\u00a8\u00a7\3\2\2\2\u00a9+\3\2\2\2\u00aa"+
		"\u00af\7\25\2\2\u00ab\u00ac\7\13\2\2\u00ac\u00ae\7\25\2\2\u00ad\u00ab"+
		"\3\2\2\2\u00ae\u00b1\3\2\2\2\u00af\u00ad\3\2\2\2\u00af\u00b0\3\2\2\2\u00b0"+
		"\u00b5\3\2\2\2\u00b1\u00af\3\2\2\2\u00b2\u00b4\5.\30\2\u00b3\u00b2\3\2"+
		"\2\2\u00b4\u00b7\3\2\2\2\u00b5\u00b3\3\2\2\2\u00b5\u00b6\3\2\2\2\u00b6"+
		"\u00b9\3\2\2\2\u00b7\u00b5\3\2\2\2\u00b8\u00ba\5\60\31\2\u00b9\u00b8\3"+
		"\2\2\2\u00b9\u00ba\3\2\2\2\u00ba\u00be\3\2\2\2\u00bb\u00bd\5\"\22\2\u00bc"+
		"\u00bb\3\2\2\2\u00bd\u00c0\3\2\2\2\u00be\u00bc\3\2\2\2\u00be\u00bf\3\2"+
		"\2\2\u00bf-\3\2\2\2\u00c0\u00be\3\2\2\2\u00c1\u00c2\7\21\2\2\u00c2\u00c3"+
		"\7\25\2\2\u00c3/\3\2\2\2\u00c4\u00c5\7\22\2\2\u00c5\61\3\2\2\2\u00c6\u00c7"+
		"\t\3\2\2\u00c7\63\3\2\2\2\u00c8\u00ca\7\23\2\2\u00c9\u00cb\5\34\17\2\u00ca"+
		"\u00c9\3\2\2\2\u00ca\u00cb\3\2\2\2\u00cb\65\3\2\2\2\u00cc\u00cf\58\35"+
		"\2\u00cd\u00cf\5:\36\2\u00ce\u00cc\3\2\2\2\u00ce\u00cd\3\2\2\2\u00cf\67"+
		"\3\2\2\2\u00d0\u00d1\7\5\2\2\u00d19\3\2\2\2\u00d2\u00d3\7\25\2\2\u00d3"+
		";\3\2\2\2\26?EV_eqx|\u0082\u0086\u008b\u0090\u0099\u00a8\u00af\u00b5\u00b9"+
		"\u00be\u00ca\u00ce";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}