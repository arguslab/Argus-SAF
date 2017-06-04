// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.jawa/src/main/java/org/argus/jawa/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.jawa.summary.grammar;
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
		T__0=1, T__1=2, T__2=3, T__3=4, T__4=5, T__5=6, T__6=7, T__7=8, UID=9, 
		ID=10, Digits=11, WS=12, COMMENT=13, LINE_COMMENT=14;
	public static String[] channelNames = {
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN"
	};

	public static String[] modeNames = {
		"DEFAULT_MODE"
	};

	public static final String[] ruleNames = {
		"T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", "T__7", "UID", 
		"ID", "Digits", "DIGIT", "LETTER", "WS", "COMMENT", "LINE_COMMENT"
	};

	private static final String[] _LITERAL_NAMES = {
		null, "':'", "';'", "'='", "'arg'", "'.'", "'@@'", "'@'", "'ret'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, null, null, null, null, null, null, null, null, "UID", "ID", "Digits", 
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
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\20r\b\1\4\2\t\2\4"+
		"\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t"+
		"\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\3\2\3\2\3"+
		"\3\3\3\3\4\3\4\3\5\3\5\3\5\3\5\3\6\3\6\3\7\3\7\3\7\3\b\3\b\3\t\3\t\3\t"+
		"\3\t\3\n\3\n\7\n;\n\n\f\n\16\n>\13\n\3\n\3\n\3\13\3\13\3\13\7\13E\n\13"+
		"\f\13\16\13H\13\13\3\f\6\fK\n\f\r\f\16\fL\3\r\3\r\3\16\3\16\3\17\6\17"+
		"T\n\17\r\17\16\17U\3\17\3\17\3\20\3\20\3\20\3\20\7\20^\n\20\f\20\16\20"+
		"a\13\20\3\20\3\20\3\20\3\20\3\20\3\21\3\21\3\21\3\21\7\21l\n\21\f\21\16"+
		"\21o\13\21\3\21\3\21\3_\2\22\3\3\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13"+
		"\25\f\27\r\31\2\33\2\35\16\37\17!\20\3\2\6\5\2\13\f\16\17bb\5\2C\\aac"+
		"|\5\2\13\f\16\17\"\"\4\2\f\f\17\17\2v\2\3\3\2\2\2\2\5\3\2\2\2\2\7\3\2"+
		"\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2\2\2\2\17\3\2\2\2\2\21\3\2\2\2\2"+
		"\23\3\2\2\2\2\25\3\2\2\2\2\27\3\2\2\2\2\35\3\2\2\2\2\37\3\2\2\2\2!\3\2"+
		"\2\2\3#\3\2\2\2\5%\3\2\2\2\7\'\3\2\2\2\t)\3\2\2\2\13-\3\2\2\2\r/\3\2\2"+
		"\2\17\62\3\2\2\2\21\64\3\2\2\2\238\3\2\2\2\25A\3\2\2\2\27J\3\2\2\2\31"+
		"N\3\2\2\2\33P\3\2\2\2\35S\3\2\2\2\37Y\3\2\2\2!g\3\2\2\2#$\7<\2\2$\4\3"+
		"\2\2\2%&\7=\2\2&\6\3\2\2\2\'(\7?\2\2(\b\3\2\2\2)*\7c\2\2*+\7t\2\2+,\7"+
		"i\2\2,\n\3\2\2\2-.\7\60\2\2.\f\3\2\2\2/\60\7B\2\2\60\61\7B\2\2\61\16\3"+
		"\2\2\2\62\63\7B\2\2\63\20\3\2\2\2\64\65\7t\2\2\65\66\7g\2\2\66\67\7v\2"+
		"\2\67\22\3\2\2\28<\7b\2\29;\n\2\2\2:9\3\2\2\2;>\3\2\2\2<:\3\2\2\2<=\3"+
		"\2\2\2=?\3\2\2\2><\3\2\2\2?@\7b\2\2@\24\3\2\2\2AF\5\33\16\2BE\5\33\16"+
		"\2CE\5\31\r\2DB\3\2\2\2DC\3\2\2\2EH\3\2\2\2FD\3\2\2\2FG\3\2\2\2G\26\3"+
		"\2\2\2HF\3\2\2\2IK\5\31\r\2JI\3\2\2\2KL\3\2\2\2LJ\3\2\2\2LM\3\2\2\2M\30"+
		"\3\2\2\2NO\4\62;\2O\32\3\2\2\2PQ\t\3\2\2Q\34\3\2\2\2RT\t\4\2\2SR\3\2\2"+
		"\2TU\3\2\2\2US\3\2\2\2UV\3\2\2\2VW\3\2\2\2WX\b\17\2\2X\36\3\2\2\2YZ\7"+
		"\61\2\2Z[\7,\2\2[_\3\2\2\2\\^\13\2\2\2]\\\3\2\2\2^a\3\2\2\2_`\3\2\2\2"+
		"_]\3\2\2\2`b\3\2\2\2a_\3\2\2\2bc\7,\2\2cd\7\61\2\2de\3\2\2\2ef\b\20\3"+
		"\2f \3\2\2\2gh\7\61\2\2hi\7\61\2\2im\3\2\2\2jl\n\5\2\2kj\3\2\2\2lo\3\2"+
		"\2\2mk\3\2\2\2mn\3\2\2\2np\3\2\2\2om\3\2\2\2pq\b\21\3\2q\"\3\2\2\2\n\2"+
		"<DFLU_m\4\2\3\2\2\4\2";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}