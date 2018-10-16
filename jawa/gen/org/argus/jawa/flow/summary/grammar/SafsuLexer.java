/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

// Generated from /Users/fengguow/IdeaProjects/Argus-SAF/jawa/src/main/java/org/argus/jawa/flow/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.jawa.flow.summary.grammar;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenStream;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.misc.*;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast"})
public class SafsuLexer extends Lexer {
	static { RuntimeMetaData.checkVersion("4.7", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		T__0=1, T__1=2, T__2=3, T__3=4, T__4=5, T__5=6, T__6=7, T__7=8, T__8=9, 
		T__9=10, T__10=11, T__11=12, T__12=13, T__13=14, T__14=15, UID=16, ID=17, 
		Digits=18, STRING=19, MSTRING=20, WS=21, COMMENT=22, LINE_COMMENT=23;
	public static String[] channelNames = {
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN"
	};

	public static String[] modeNames = {
		"DEFAULT_MODE"
	};

	public static final String[] ruleNames = {
		"T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", "T__7", "T__8", 
		"T__9", "T__10", "T__11", "T__12", "T__13", "T__14", "UID", "ID", "Digits", 
		"STRING", "MSTRING", "EscapeSequence", "DIGIT", "LETTER", "WS", "COMMENT", 
		"LINE_COMMENT"
	};

	private static final String[] _LITERAL_NAMES = {
		null, "':'", "';'", "'~'", "'='", "'+='", "'-='", "'this'", "'arg'", "'.'", 
		"'[]'", "'@'", "'classOf'", "'$'", "'?'", "'ret'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, null, null, null, null, null, null, null, null, null, null, null, 
		null, null, null, null, "UID", "ID", "Digits", "STRING", "MSTRING", "WS", 
		"COMMENT", "LINE_COMMENT"
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


	public SafsuLexer(CharStream input) {
		super(input);
		_interp = new LexerATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	@Override
	public String getGrammarFileName() { return "Safsu.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public String[] getChannelNames() { return channelNames; }

	@Override
	public String[] getModeNames() { return modeNames; }

	@Override
	public ATN getATN() { return _ATN; }

	public static final String _serializedATN =
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\31\u00ba\b\1\4\2"+
		"\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4"+
		"\13\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22"+
		"\t\22\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31"+
		"\t\31\4\32\t\32\4\33\t\33\3\2\3\2\3\3\3\3\3\4\3\4\3\5\3\5\3\6\3\6\3\6"+
		"\3\7\3\7\3\7\3\b\3\b\3\b\3\b\3\b\3\t\3\t\3\t\3\t\3\n\3\n\3\13\3\13\3\13"+
		"\3\f\3\f\3\r\3\r\3\r\3\r\3\r\3\r\3\r\3\r\3\16\3\16\3\17\3\17\3\20\3\20"+
		"\3\20\3\20\3\21\3\21\7\21h\n\21\f\21\16\21k\13\21\3\21\3\21\3\22\3\22"+
		"\3\22\7\22r\n\22\f\22\16\22u\13\22\3\23\6\23x\n\23\r\23\16\23y\3\24\3"+
		"\24\3\24\7\24\177\n\24\f\24\16\24\u0082\13\24\3\24\3\24\3\25\3\25\3\25"+
		"\3\25\3\25\7\25\u008b\n\25\f\25\16\25\u008e\13\25\3\25\3\25\3\25\3\25"+
		"\3\26\3\26\3\26\3\27\3\27\3\30\3\30\3\31\6\31\u009c\n\31\r\31\16\31\u009d"+
		"\3\31\3\31\3\32\3\32\3\32\3\32\7\32\u00a6\n\32\f\32\16\32\u00a9\13\32"+
		"\3\32\3\32\3\32\3\32\3\32\3\33\3\33\3\33\3\33\7\33\u00b4\n\33\f\33\16"+
		"\33\u00b7\13\33\3\33\3\33\4\u008c\u00a7\2\34\3\3\5\4\7\5\t\6\13\7\r\b"+
		"\17\t\21\n\23\13\25\f\27\r\31\16\33\17\35\20\37\21!\22#\23%\24\'\25)\26"+
		"+\2-\2/\2\61\27\63\30\65\31\3\2\b\5\2\13\f\16\17bb\4\2$$^^\n\2$$))^^d"+
		"dhhppttvv\5\2C\\aac|\5\2\13\f\16\17\"\"\4\2\f\f\17\17\2\u00c0\2\3\3\2"+
		"\2\2\2\5\3\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2\2\2\2\17"+
		"\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2\25\3\2\2\2\2\27\3\2\2\2\2\31\3\2"+
		"\2\2\2\33\3\2\2\2\2\35\3\2\2\2\2\37\3\2\2\2\2!\3\2\2\2\2#\3\2\2\2\2%\3"+
		"\2\2\2\2\'\3\2\2\2\2)\3\2\2\2\2\61\3\2\2\2\2\63\3\2\2\2\2\65\3\2\2\2\3"+
		"\67\3\2\2\2\59\3\2\2\2\7;\3\2\2\2\t=\3\2\2\2\13?\3\2\2\2\rB\3\2\2\2\17"+
		"E\3\2\2\2\21J\3\2\2\2\23N\3\2\2\2\25P\3\2\2\2\27S\3\2\2\2\31U\3\2\2\2"+
		"\33]\3\2\2\2\35_\3\2\2\2\37a\3\2\2\2!e\3\2\2\2#n\3\2\2\2%w\3\2\2\2\'{"+
		"\3\2\2\2)\u0085\3\2\2\2+\u0093\3\2\2\2-\u0096\3\2\2\2/\u0098\3\2\2\2\61"+
		"\u009b\3\2\2\2\63\u00a1\3\2\2\2\65\u00af\3\2\2\2\678\7<\2\28\4\3\2\2\2"+
		"9:\7=\2\2:\6\3\2\2\2;<\7\u0080\2\2<\b\3\2\2\2=>\7?\2\2>\n\3\2\2\2?@\7"+
		"-\2\2@A\7?\2\2A\f\3\2\2\2BC\7/\2\2CD\7?\2\2D\16\3\2\2\2EF\7v\2\2FG\7j"+
		"\2\2GH\7k\2\2HI\7u\2\2I\20\3\2\2\2JK\7c\2\2KL\7t\2\2LM\7i\2\2M\22\3\2"+
		"\2\2NO\7\60\2\2O\24\3\2\2\2PQ\7]\2\2QR\7_\2\2R\26\3\2\2\2ST\7B\2\2T\30"+
		"\3\2\2\2UV\7e\2\2VW\7n\2\2WX\7c\2\2XY\7u\2\2YZ\7u\2\2Z[\7Q\2\2[\\\7h\2"+
		"\2\\\32\3\2\2\2]^\7&\2\2^\34\3\2\2\2_`\7A\2\2`\36\3\2\2\2ab\7t\2\2bc\7"+
		"g\2\2cd\7v\2\2d \3\2\2\2ei\7b\2\2fh\n\2\2\2gf\3\2\2\2hk\3\2\2\2ig\3\2"+
		"\2\2ij\3\2\2\2jl\3\2\2\2ki\3\2\2\2lm\7b\2\2m\"\3\2\2\2ns\5/\30\2or\5/"+
		"\30\2pr\5-\27\2qo\3\2\2\2qp\3\2\2\2ru\3\2\2\2sq\3\2\2\2st\3\2\2\2t$\3"+
		"\2\2\2us\3\2\2\2vx\5-\27\2wv\3\2\2\2xy\3\2\2\2yw\3\2\2\2yz\3\2\2\2z&\3"+
		"\2\2\2{\u0080\7$\2\2|\177\5+\26\2}\177\n\3\2\2~|\3\2\2\2~}\3\2\2\2\177"+
		"\u0082\3\2\2\2\u0080~\3\2\2\2\u0080\u0081\3\2\2\2\u0081\u0083\3\2\2\2"+
		"\u0082\u0080\3\2\2\2\u0083\u0084\7$\2\2\u0084(\3\2\2\2\u0085\u0086\7$"+
		"\2\2\u0086\u0087\7$\2\2\u0087\u0088\7$\2\2\u0088\u008c\3\2\2\2\u0089\u008b"+
		"\13\2\2\2\u008a\u0089\3\2\2\2\u008b\u008e\3\2\2\2\u008c\u008d\3\2\2\2"+
		"\u008c\u008a\3\2\2\2\u008d\u008f\3\2\2\2\u008e\u008c\3\2\2\2\u008f\u0090"+
		"\7$\2\2\u0090\u0091\7$\2\2\u0091\u0092\7$\2\2\u0092*\3\2\2\2\u0093\u0094"+
		"\7^\2\2\u0094\u0095\t\4\2\2\u0095,\3\2\2\2\u0096\u0097\4\62;\2\u0097."+
		"\3\2\2\2\u0098\u0099\t\5\2\2\u0099\60\3\2\2\2\u009a\u009c\t\6\2\2\u009b"+
		"\u009a\3\2\2\2\u009c\u009d\3\2\2\2\u009d\u009b\3\2\2\2\u009d\u009e\3\2"+
		"\2\2\u009e\u009f\3\2\2\2\u009f\u00a0\b\31\2\2\u00a0\62\3\2\2\2\u00a1\u00a2"+
		"\7\61\2\2\u00a2\u00a3\7,\2\2\u00a3\u00a7\3\2\2\2\u00a4\u00a6\13\2\2\2"+
		"\u00a5\u00a4\3\2\2\2\u00a6\u00a9\3\2\2\2\u00a7\u00a8\3\2\2\2\u00a7\u00a5"+
		"\3\2\2\2\u00a8\u00aa\3\2\2\2\u00a9\u00a7\3\2\2\2\u00aa\u00ab\7,\2\2\u00ab"+
		"\u00ac\7\61\2\2\u00ac\u00ad\3\2\2\2\u00ad\u00ae\b\32\3\2\u00ae\64\3\2"+
		"\2\2\u00af\u00b0\7\61\2\2\u00b0\u00b1\7\61\2\2\u00b1\u00b5\3\2\2\2\u00b2"+
		"\u00b4\n\7\2\2\u00b3\u00b2\3\2\2\2\u00b4\u00b7\3\2\2\2\u00b5\u00b3\3\2"+
		"\2\2\u00b5\u00b6\3\2\2\2\u00b6\u00b8\3\2\2\2\u00b7\u00b5\3\2\2\2\u00b8"+
		"\u00b9\b\33\3\2\u00b9\66\3\2\2\2\r\2iqsy~\u0080\u008c\u009d\u00a7\u00b5"+
		"\4\2\3\2\2\4\2";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}