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
		T__9=10, T__10=11, T__11=12, UID=13, ID=14, Digits=15, WS=16, COMMENT=17, 
		LINE_COMMENT=18;
	public static final int
		RULE_summaryFile = 0, RULE_summary = 1, RULE_signature = 2, RULE_suRule = 3, 
		RULE_clearRule = 4, RULE_binaryRule = 5, RULE_ops = 6, RULE_lhs = 7, RULE_rhs = 8, 
		RULE_suThis = 9, RULE_arg = 10, RULE_global = 11, RULE_heap = 12, RULE_heapAccess = 13, 
		RULE_fieldAccess = 14, RULE_arrayAccess = 15, RULE_type = 16, RULE_ret = 17, 
		RULE_location = 18, RULE_virtualLocation = 19, RULE_concreteLocation = 20;
	public static final String[] ruleNames = {
		"summaryFile", "summary", "signature", "suRule", "clearRule", "binaryRule", 
		"ops", "lhs", "rhs", "suThis", "arg", "global", "heap", "heapAccess", 
		"fieldAccess", "arrayAccess", "type", "ret", "location", "virtualLocation", 
		"concreteLocation"
	};

	private static final String[] _LITERAL_NAMES = {
		null, "':'", "';'", "'~'", "'='", "'+='", "'-='", "'this'", "'arg'", "'.'", 
		"'[]'", "'@'", "'ret'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, null, null, null, null, null, null, null, null, null, null, null, 
		null, "UID", "ID", "Digits", "WS", "COMMENT", "LINE_COMMENT"
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
			setState(45);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==UID) {
				{
				{
				setState(42);
				summary();
				}
				}
				setState(47);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(48);
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
		enterRule(_localctx, 2, RULE_summary);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(50);
			signature();
			setState(51);
			match(T__0);
			setState(55);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while ((((_la) & ~0x3f) == 0 && ((1L << _la) & ((1L << T__2) | (1L << T__6) | (1L << T__7) | (1L << T__11) | (1L << UID))) != 0)) {
				{
				{
				setState(52);
				suRule();
				}
				}
				setState(57);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(58);
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
		enterRule(_localctx, 4, RULE_signature);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(60);
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
		enterRule(_localctx, 6, RULE_suRule);
		try {
			setState(64);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__2:
				enterOuterAlt(_localctx, 1);
				{
				setState(62);
				clearRule();
				}
				break;
			case T__6:
			case T__7:
			case T__11:
			case UID:
				enterOuterAlt(_localctx, 2);
				{
				setState(63);
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
		enterRule(_localctx, 8, RULE_clearRule);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(66);
			match(T__2);
			setState(70);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				{
				setState(67);
				suThis();
				}
				break;
			case T__7:
				{
				setState(68);
				arg();
				}
				break;
			case UID:
				{
				setState(69);
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
		enterRule(_localctx, 10, RULE_binaryRule);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(72);
			lhs();
			setState(73);
			ops();
			setState(74);
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
		enterRule(_localctx, 12, RULE_ops);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(76);
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
		enterRule(_localctx, 14, RULE_lhs);
		try {
			setState(82);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				enterOuterAlt(_localctx, 1);
				{
				setState(78);
				suThis();
				}
				break;
			case T__7:
				enterOuterAlt(_localctx, 2);
				{
				setState(79);
				arg();
				}
				break;
			case UID:
				enterOuterAlt(_localctx, 3);
				{
				setState(80);
				global();
				}
				break;
			case T__11:
				enterOuterAlt(_localctx, 4);
				{
				setState(81);
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
		public TypeContext type() {
			return getRuleContext(TypeContext.class,0);
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
		enterRule(_localctx, 16, RULE_rhs);
		try {
			setState(88);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__6:
				enterOuterAlt(_localctx, 1);
				{
				setState(84);
				suThis();
				}
				break;
			case T__7:
				enterOuterAlt(_localctx, 2);
				{
				setState(85);
				arg();
				}
				break;
			case UID:
				enterOuterAlt(_localctx, 3);
				{
				setState(86);
				global();
				}
				break;
			case ID:
				enterOuterAlt(_localctx, 4);
				{
				setState(87);
				type();
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
		enterRule(_localctx, 18, RULE_suThis);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(90);
			match(T__6);
			setState(92);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__8 || _la==T__9) {
				{
				setState(91);
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
		enterRule(_localctx, 20, RULE_arg);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(94);
			match(T__7);
			setState(95);
			match(T__0);
			setState(96);
			match(Digits);
			setState(98);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__8 || _la==T__9) {
				{
				setState(97);
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
		enterRule(_localctx, 22, RULE_global);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(100);
			match(UID);
			setState(102);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__8 || _la==T__9) {
				{
				setState(101);
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
		enterRule(_localctx, 24, RULE_heap);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(105); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(104);
				heapAccess();
				}
				}
				setState(107); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( _la==T__8 || _la==T__9 );
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
		enterRule(_localctx, 26, RULE_heapAccess);
		try {
			setState(111);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__8:
				enterOuterAlt(_localctx, 1);
				{
				setState(109);
				fieldAccess();
				}
				break;
			case T__9:
				enterOuterAlt(_localctx, 2);
				{
				setState(110);
				arrayAccess();
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
		enterRule(_localctx, 28, RULE_fieldAccess);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(113);
			match(T__8);
			setState(114);
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
		enterRule(_localctx, 30, RULE_arrayAccess);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(116);
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

	public static class TypeContext extends ParserRuleContext {
		public List<TerminalNode> ID() { return getTokens(SafsuParser.ID); }
		public TerminalNode ID(int i) {
			return getToken(SafsuParser.ID, i);
		}
		public LocationContext location() {
			return getRuleContext(LocationContext.class,0);
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
		enterRule(_localctx, 32, RULE_type);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(118);
			match(ID);
			setState(123);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__8) {
				{
				{
				setState(119);
				match(T__8);
				setState(120);
				match(ID);
				}
				}
				setState(125);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(126);
			match(T__10);
			setState(127);
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
		enterRule(_localctx, 34, RULE_ret);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(129);
			match(T__11);
			setState(131);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__8 || _la==T__9) {
				{
				setState(130);
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
		enterRule(_localctx, 36, RULE_location);
		try {
			setState(135);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case T__2:
				enterOuterAlt(_localctx, 1);
				{
				setState(133);
				virtualLocation();
				}
				break;
			case ID:
				enterOuterAlt(_localctx, 2);
				{
				setState(134);
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
		enterRule(_localctx, 38, RULE_virtualLocation);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(137);
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
		enterRule(_localctx, 40, RULE_concreteLocation);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(139);
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
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3\24\u0090\4\2\t\2"+
		"\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13"+
		"\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22\t\22"+
		"\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\3\2\7\2.\n\2\f\2\16\2\61\13\2"+
		"\3\2\3\2\3\3\3\3\3\3\7\38\n\3\f\3\16\3;\13\3\3\3\3\3\3\4\3\4\3\5\3\5\5"+
		"\5C\n\5\3\6\3\6\3\6\3\6\5\6I\n\6\3\7\3\7\3\7\3\7\3\b\3\b\3\t\3\t\3\t\3"+
		"\t\5\tU\n\t\3\n\3\n\3\n\3\n\5\n[\n\n\3\13\3\13\5\13_\n\13\3\f\3\f\3\f"+
		"\3\f\5\fe\n\f\3\r\3\r\5\ri\n\r\3\16\6\16l\n\16\r\16\16\16m\3\17\3\17\5"+
		"\17r\n\17\3\20\3\20\3\20\3\21\3\21\3\22\3\22\3\22\7\22|\n\22\f\22\16\22"+
		"\177\13\22\3\22\3\22\3\22\3\23\3\23\5\23\u0086\n\23\3\24\3\24\5\24\u008a"+
		"\n\24\3\25\3\25\3\26\3\26\3\26\2\2\27\2\4\6\b\n\f\16\20\22\24\26\30\32"+
		"\34\36 \"$&(*\2\3\3\2\6\b\2\u008d\2/\3\2\2\2\4\64\3\2\2\2\6>\3\2\2\2\b"+
		"B\3\2\2\2\nD\3\2\2\2\fJ\3\2\2\2\16N\3\2\2\2\20T\3\2\2\2\22Z\3\2\2\2\24"+
		"\\\3\2\2\2\26`\3\2\2\2\30f\3\2\2\2\32k\3\2\2\2\34q\3\2\2\2\36s\3\2\2\2"+
		" v\3\2\2\2\"x\3\2\2\2$\u0083\3\2\2\2&\u0089\3\2\2\2(\u008b\3\2\2\2*\u008d"+
		"\3\2\2\2,.\5\4\3\2-,\3\2\2\2.\61\3\2\2\2/-\3\2\2\2/\60\3\2\2\2\60\62\3"+
		"\2\2\2\61/\3\2\2\2\62\63\7\2\2\3\63\3\3\2\2\2\64\65\5\6\4\2\659\7\3\2"+
		"\2\668\5\b\5\2\67\66\3\2\2\28;\3\2\2\29\67\3\2\2\29:\3\2\2\2:<\3\2\2\2"+
		";9\3\2\2\2<=\7\4\2\2=\5\3\2\2\2>?\7\17\2\2?\7\3\2\2\2@C\5\n\6\2AC\5\f"+
		"\7\2B@\3\2\2\2BA\3\2\2\2C\t\3\2\2\2DH\7\5\2\2EI\5\24\13\2FI\5\26\f\2G"+
		"I\5\30\r\2HE\3\2\2\2HF\3\2\2\2HG\3\2\2\2I\13\3\2\2\2JK\5\20\t\2KL\5\16"+
		"\b\2LM\5\22\n\2M\r\3\2\2\2NO\t\2\2\2O\17\3\2\2\2PU\5\24\13\2QU\5\26\f"+
		"\2RU\5\30\r\2SU\5$\23\2TP\3\2\2\2TQ\3\2\2\2TR\3\2\2\2TS\3\2\2\2U\21\3"+
		"\2\2\2V[\5\24\13\2W[\5\26\f\2X[\5\30\r\2Y[\5\"\22\2ZV\3\2\2\2ZW\3\2\2"+
		"\2ZX\3\2\2\2ZY\3\2\2\2[\23\3\2\2\2\\^\7\t\2\2]_\5\32\16\2^]\3\2\2\2^_"+
		"\3\2\2\2_\25\3\2\2\2`a\7\n\2\2ab\7\3\2\2bd\7\21\2\2ce\5\32\16\2dc\3\2"+
		"\2\2de\3\2\2\2e\27\3\2\2\2fh\7\17\2\2gi\5\32\16\2hg\3\2\2\2hi\3\2\2\2"+
		"i\31\3\2\2\2jl\5\34\17\2kj\3\2\2\2lm\3\2\2\2mk\3\2\2\2mn\3\2\2\2n\33\3"+
		"\2\2\2or\5\36\20\2pr\5 \21\2qo\3\2\2\2qp\3\2\2\2r\35\3\2\2\2st\7\13\2"+
		"\2tu\7\20\2\2u\37\3\2\2\2vw\7\f\2\2w!\3\2\2\2x}\7\20\2\2yz\7\13\2\2z|"+
		"\7\20\2\2{y\3\2\2\2|\177\3\2\2\2}{\3\2\2\2}~\3\2\2\2~\u0080\3\2\2\2\177"+
		"}\3\2\2\2\u0080\u0081\7\r\2\2\u0081\u0082\5&\24\2\u0082#\3\2\2\2\u0083"+
		"\u0085\7\16\2\2\u0084\u0086\5\32\16\2\u0085\u0084\3\2\2\2\u0085\u0086"+
		"\3\2\2\2\u0086%\3\2\2\2\u0087\u008a\5(\25\2\u0088\u008a\5*\26\2\u0089"+
		"\u0087\3\2\2\2\u0089\u0088\3\2\2\2\u008a\'\3\2\2\2\u008b\u008c\7\5\2\2"+
		"\u008c)\3\2\2\2\u008d\u008e\7\20\2\2\u008e+\3\2\2\2\20/9BHTZ^dhmq}\u0085"+
		"\u0089";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}