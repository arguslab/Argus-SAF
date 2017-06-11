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
		T__9=10, T__10=11, T__11=12, UID=13, ID=14, Digits=15, STRING=16, MSTRING=17, 
		WS=18, COMMENT=19, LINE_COMMENT=20;
	public static String[] channelNames = {
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN"
	};

	public static String[] modeNames = {
		"DEFAULT_MODE"
	};

	public static final String[] ruleNames = {
		"T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", "T__7", "T__8", 
		"T__9", "T__10", "T__11", "UID", "ID", "Digits", "STRING", "MSTRING", 
		"EscapeSequence", "DIGIT", "LETTER", "WS", "COMMENT", "LINE_COMMENT"
	};

	private static final String[] _LITERAL_NAMES = {
		null, "':'", "';'", "'~'", "'='", "'+='", "'-='", "'this'", "'arg'", "'.'", 
		"'[]'", "'@'", "'ret'"
	};
	private static final String[] _SYMBOLIC_NAMES = {
		null, null, null, null, null, null, null, null, null, null, null, null, 
		null, "UID", "ID", "Digits", "STRING", "MSTRING", "WS", "COMMENT", "LINE_COMMENT"
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
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\26\u00a8\b\1\4\2"+
		"\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4"+
		"\13\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22"+
		"\t\22\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\3\2"+
		"\3\2\3\3\3\3\3\4\3\4\3\5\3\5\3\6\3\6\3\6\3\7\3\7\3\7\3\b\3\b\3\b\3\b\3"+
		"\b\3\t\3\t\3\t\3\t\3\n\3\n\3\13\3\13\3\13\3\f\3\f\3\r\3\r\3\r\3\r\3\16"+
		"\3\16\7\16V\n\16\f\16\16\16Y\13\16\3\16\3\16\3\17\3\17\3\17\7\17`\n\17"+
		"\f\17\16\17c\13\17\3\20\6\20f\n\20\r\20\16\20g\3\21\3\21\3\21\7\21m\n"+
		"\21\f\21\16\21p\13\21\3\21\3\21\3\22\3\22\3\22\3\22\3\22\7\22y\n\22\f"+
		"\22\16\22|\13\22\3\22\3\22\3\22\3\22\3\23\3\23\3\23\3\24\3\24\3\25\3\25"+
		"\3\26\6\26\u008a\n\26\r\26\16\26\u008b\3\26\3\26\3\27\3\27\3\27\3\27\7"+
		"\27\u0094\n\27\f\27\16\27\u0097\13\27\3\27\3\27\3\27\3\27\3\27\3\30\3"+
		"\30\3\30\3\30\7\30\u00a2\n\30\f\30\16\30\u00a5\13\30\3\30\3\30\4z\u0095"+
		"\2\31\3\3\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13\25\f\27\r\31\16\33\17\35"+
		"\20\37\21!\22#\23%\2\'\2)\2+\24-\25/\26\3\2\b\5\2\13\f\16\17bb\4\2$$^"+
		"^\n\2$$))^^ddhhppttvv\5\2C\\aac|\5\2\13\f\16\17\"\"\4\2\f\f\17\17\2\u00ae"+
		"\2\3\3\2\2\2\2\5\3\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2"+
		"\2\2\2\17\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2\25\3\2\2\2\2\27\3\2\2\2"+
		"\2\31\3\2\2\2\2\33\3\2\2\2\2\35\3\2\2\2\2\37\3\2\2\2\2!\3\2\2\2\2#\3\2"+
		"\2\2\2+\3\2\2\2\2-\3\2\2\2\2/\3\2\2\2\3\61\3\2\2\2\5\63\3\2\2\2\7\65\3"+
		"\2\2\2\t\67\3\2\2\2\139\3\2\2\2\r<\3\2\2\2\17?\3\2\2\2\21D\3\2\2\2\23"+
		"H\3\2\2\2\25J\3\2\2\2\27M\3\2\2\2\31O\3\2\2\2\33S\3\2\2\2\35\\\3\2\2\2"+
		"\37e\3\2\2\2!i\3\2\2\2#s\3\2\2\2%\u0081\3\2\2\2\'\u0084\3\2\2\2)\u0086"+
		"\3\2\2\2+\u0089\3\2\2\2-\u008f\3\2\2\2/\u009d\3\2\2\2\61\62\7<\2\2\62"+
		"\4\3\2\2\2\63\64\7=\2\2\64\6\3\2\2\2\65\66\7\u0080\2\2\66\b\3\2\2\2\67"+
		"8\7?\2\28\n\3\2\2\29:\7-\2\2:;\7?\2\2;\f\3\2\2\2<=\7/\2\2=>\7?\2\2>\16"+
		"\3\2\2\2?@\7v\2\2@A\7j\2\2AB\7k\2\2BC\7u\2\2C\20\3\2\2\2DE\7c\2\2EF\7"+
		"t\2\2FG\7i\2\2G\22\3\2\2\2HI\7\60\2\2I\24\3\2\2\2JK\7]\2\2KL\7_\2\2L\26"+
		"\3\2\2\2MN\7B\2\2N\30\3\2\2\2OP\7t\2\2PQ\7g\2\2QR\7v\2\2R\32\3\2\2\2S"+
		"W\7b\2\2TV\n\2\2\2UT\3\2\2\2VY\3\2\2\2WU\3\2\2\2WX\3\2\2\2XZ\3\2\2\2Y"+
		"W\3\2\2\2Z[\7b\2\2[\34\3\2\2\2\\a\5)\25\2]`\5)\25\2^`\5\'\24\2_]\3\2\2"+
		"\2_^\3\2\2\2`c\3\2\2\2a_\3\2\2\2ab\3\2\2\2b\36\3\2\2\2ca\3\2\2\2df\5\'"+
		"\24\2ed\3\2\2\2fg\3\2\2\2ge\3\2\2\2gh\3\2\2\2h \3\2\2\2in\7$\2\2jm\5%"+
		"\23\2km\n\3\2\2lj\3\2\2\2lk\3\2\2\2mp\3\2\2\2nl\3\2\2\2no\3\2\2\2oq\3"+
		"\2\2\2pn\3\2\2\2qr\7$\2\2r\"\3\2\2\2st\7$\2\2tu\7$\2\2uv\7$\2\2vz\3\2"+
		"\2\2wy\13\2\2\2xw\3\2\2\2y|\3\2\2\2z{\3\2\2\2zx\3\2\2\2{}\3\2\2\2|z\3"+
		"\2\2\2}~\7$\2\2~\177\7$\2\2\177\u0080\7$\2\2\u0080$\3\2\2\2\u0081\u0082"+
		"\7^\2\2\u0082\u0083\t\4\2\2\u0083&\3\2\2\2\u0084\u0085\4\62;\2\u0085("+
		"\3\2\2\2\u0086\u0087\t\5\2\2\u0087*\3\2\2\2\u0088\u008a\t\6\2\2\u0089"+
		"\u0088\3\2\2\2\u008a\u008b\3\2\2\2\u008b\u0089\3\2\2\2\u008b\u008c\3\2"+
		"\2\2\u008c\u008d\3\2\2\2\u008d\u008e\b\26\2\2\u008e,\3\2\2\2\u008f\u0090"+
		"\7\61\2\2\u0090\u0091\7,\2\2\u0091\u0095\3\2\2\2\u0092\u0094\13\2\2\2"+
		"\u0093\u0092\3\2\2\2\u0094\u0097\3\2\2\2\u0095\u0096\3\2\2\2\u0095\u0093"+
		"\3\2\2\2\u0096\u0098\3\2\2\2\u0097\u0095\3\2\2\2\u0098\u0099\7,\2\2\u0099"+
		"\u009a\7\61\2\2\u009a\u009b\3\2\2\2\u009b\u009c\b\27\3\2\u009c.\3\2\2"+
		"\2\u009d\u009e\7\61\2\2\u009e\u009f\7\61\2\2\u009f\u00a3\3\2\2\2\u00a0"+
		"\u00a2\n\7\2\2\u00a1\u00a0\3\2\2\2\u00a2\u00a5\3\2\2\2\u00a3\u00a1\3\2"+
		"\2\2\u00a3\u00a4\3\2\2\2\u00a4\u00a6\3\2\2\2\u00a5\u00a3\3\2\2\2\u00a6"+
		"\u00a7\b\30\3\2\u00a7\60\3\2\2\2\r\2W_aglnz\u008b\u0095\u00a3\4\2\3\2"+
		"\2\4\2";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}