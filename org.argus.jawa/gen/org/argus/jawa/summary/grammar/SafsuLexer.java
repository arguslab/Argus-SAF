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
		"'[]'", "'('", "')'", "'@'", "'?'", "'ret'"
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
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\31\u00b4\b\1\4\2"+
		"\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4"+
		"\13\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22"+
		"\t\22\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31"+
		"\t\31\4\32\t\32\4\33\t\33\3\2\3\2\3\3\3\3\3\4\3\4\3\5\3\5\3\6\3\6\3\6"+
		"\3\7\3\7\3\7\3\b\3\b\3\b\3\b\3\b\3\t\3\t\3\t\3\t\3\n\3\n\3\13\3\13\3\13"+
		"\3\f\3\f\3\r\3\r\3\16\3\16\3\17\3\17\3\20\3\20\3\20\3\20\3\21\3\21\7\21"+
		"b\n\21\f\21\16\21e\13\21\3\21\3\21\3\22\3\22\3\22\7\22l\n\22\f\22\16\22"+
		"o\13\22\3\23\6\23r\n\23\r\23\16\23s\3\24\3\24\3\24\7\24y\n\24\f\24\16"+
		"\24|\13\24\3\24\3\24\3\25\3\25\3\25\3\25\3\25\7\25\u0085\n\25\f\25\16"+
		"\25\u0088\13\25\3\25\3\25\3\25\3\25\3\26\3\26\3\26\3\27\3\27\3\30\3\30"+
		"\3\31\6\31\u0096\n\31\r\31\16\31\u0097\3\31\3\31\3\32\3\32\3\32\3\32\7"+
		"\32\u00a0\n\32\f\32\16\32\u00a3\13\32\3\32\3\32\3\32\3\32\3\32\3\33\3"+
		"\33\3\33\3\33\7\33\u00ae\n\33\f\33\16\33\u00b1\13\33\3\33\3\33\4\u0086"+
		"\u00a1\2\34\3\3\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13\25\f\27\r\31\16\33"+
		"\17\35\20\37\21!\22#\23%\24\'\25)\26+\2-\2/\2\61\27\63\30\65\31\3\2\b"+
		"\5\2\13\f\16\17bb\4\2$$^^\n\2$$))^^ddhhppttvv\5\2C\\aac|\5\2\13\f\16\17"+
		"\"\"\4\2\f\f\17\17\2\u00ba\2\3\3\2\2\2\2\5\3\2\2\2\2\7\3\2\2\2\2\t\3\2"+
		"\2\2\2\13\3\2\2\2\2\r\3\2\2\2\2\17\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2"+
		"\25\3\2\2\2\2\27\3\2\2\2\2\31\3\2\2\2\2\33\3\2\2\2\2\35\3\2\2\2\2\37\3"+
		"\2\2\2\2!\3\2\2\2\2#\3\2\2\2\2%\3\2\2\2\2\'\3\2\2\2\2)\3\2\2\2\2\61\3"+
		"\2\2\2\2\63\3\2\2\2\2\65\3\2\2\2\3\67\3\2\2\2\59\3\2\2\2\7;\3\2\2\2\t"+
		"=\3\2\2\2\13?\3\2\2\2\rB\3\2\2\2\17E\3\2\2\2\21J\3\2\2\2\23N\3\2\2\2\25"+
		"P\3\2\2\2\27S\3\2\2\2\31U\3\2\2\2\33W\3\2\2\2\35Y\3\2\2\2\37[\3\2\2\2"+
		"!_\3\2\2\2#h\3\2\2\2%q\3\2\2\2\'u\3\2\2\2)\177\3\2\2\2+\u008d\3\2\2\2"+
		"-\u0090\3\2\2\2/\u0092\3\2\2\2\61\u0095\3\2\2\2\63\u009b\3\2\2\2\65\u00a9"+
		"\3\2\2\2\678\7<\2\28\4\3\2\2\29:\7=\2\2:\6\3\2\2\2;<\7\u0080\2\2<\b\3"+
		"\2\2\2=>\7?\2\2>\n\3\2\2\2?@\7-\2\2@A\7?\2\2A\f\3\2\2\2BC\7/\2\2CD\7?"+
		"\2\2D\16\3\2\2\2EF\7v\2\2FG\7j\2\2GH\7k\2\2HI\7u\2\2I\20\3\2\2\2JK\7c"+
		"\2\2KL\7t\2\2LM\7i\2\2M\22\3\2\2\2NO\7\60\2\2O\24\3\2\2\2PQ\7]\2\2QR\7"+
		"_\2\2R\26\3\2\2\2ST\7*\2\2T\30\3\2\2\2UV\7+\2\2V\32\3\2\2\2WX\7B\2\2X"+
		"\34\3\2\2\2YZ\7A\2\2Z\36\3\2\2\2[\\\7t\2\2\\]\7g\2\2]^\7v\2\2^ \3\2\2"+
		"\2_c\7b\2\2`b\n\2\2\2a`\3\2\2\2be\3\2\2\2ca\3\2\2\2cd\3\2\2\2df\3\2\2"+
		"\2ec\3\2\2\2fg\7b\2\2g\"\3\2\2\2hm\5/\30\2il\5/\30\2jl\5-\27\2ki\3\2\2"+
		"\2kj\3\2\2\2lo\3\2\2\2mk\3\2\2\2mn\3\2\2\2n$\3\2\2\2om\3\2\2\2pr\5-\27"+
		"\2qp\3\2\2\2rs\3\2\2\2sq\3\2\2\2st\3\2\2\2t&\3\2\2\2uz\7$\2\2vy\5+\26"+
		"\2wy\n\3\2\2xv\3\2\2\2xw\3\2\2\2y|\3\2\2\2zx\3\2\2\2z{\3\2\2\2{}\3\2\2"+
		"\2|z\3\2\2\2}~\7$\2\2~(\3\2\2\2\177\u0080\7$\2\2\u0080\u0081\7$\2\2\u0081"+
		"\u0082\7$\2\2\u0082\u0086\3\2\2\2\u0083\u0085\13\2\2\2\u0084\u0083\3\2"+
		"\2\2\u0085\u0088\3\2\2\2\u0086\u0087\3\2\2\2\u0086\u0084\3\2\2\2\u0087"+
		"\u0089\3\2\2\2\u0088\u0086\3\2\2\2\u0089\u008a\7$\2\2\u008a\u008b\7$\2"+
		"\2\u008b\u008c\7$\2\2\u008c*\3\2\2\2\u008d\u008e\7^\2\2\u008e\u008f\t"+
		"\4\2\2\u008f,\3\2\2\2\u0090\u0091\4\62;\2\u0091.\3\2\2\2\u0092\u0093\t"+
		"\5\2\2\u0093\60\3\2\2\2\u0094\u0096\t\6\2\2\u0095\u0094\3\2\2\2\u0096"+
		"\u0097\3\2\2\2\u0097\u0095\3\2\2\2\u0097\u0098\3\2\2\2\u0098\u0099\3\2"+
		"\2\2\u0099\u009a\b\31\2\2\u009a\62\3\2\2\2\u009b\u009c\7\61\2\2\u009c"+
		"\u009d\7,\2\2\u009d\u00a1\3\2\2\2\u009e\u00a0\13\2\2\2\u009f\u009e\3\2"+
		"\2\2\u00a0\u00a3\3\2\2\2\u00a1\u00a2\3\2\2\2\u00a1\u009f\3\2\2\2\u00a2"+
		"\u00a4\3\2\2\2\u00a3\u00a1\3\2\2\2\u00a4\u00a5\7,\2\2\u00a5\u00a6\7\61"+
		"\2\2\u00a6\u00a7\3\2\2\2\u00a7\u00a8\b\32\3\2\u00a8\64\3\2\2\2\u00a9\u00aa"+
		"\7\61\2\2\u00aa\u00ab\7\61\2\2\u00ab\u00af\3\2\2\2\u00ac\u00ae\n\7\2\2"+
		"\u00ad\u00ac\3\2\2\2\u00ae\u00b1\3\2\2\2\u00af\u00ad\3\2\2\2\u00af\u00b0"+
		"\3\2\2\2\u00b0\u00b2\3\2\2\2\u00b1\u00af\3\2\2\2\u00b2\u00b3\b\33\3\2"+
		"\u00b3\66\3\2\2\2\r\2ckmsxz\u0086\u0097\u00a1\u00af\4\2\3\2\2\4\2";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}