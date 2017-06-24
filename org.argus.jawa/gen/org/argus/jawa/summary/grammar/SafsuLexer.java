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
		T__9=10, T__10=11, T__11=12, T__12=13, T__13=14, T__14=15, T__15=16, T__16=17, 
		UID=18, ID=19, Digits=20, STRING=21, MSTRING=22, WS=23, COMMENT=24, LINE_COMMENT=25;
	public static String[] channelNames = {
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN"
	};

	public static String[] modeNames = {
		"DEFAULT_MODE"
	};

	public static final String[] ruleNames = {
		"T__0", "T__1", "T__2", "T__3", "T__4", "T__5", "T__6", "T__7", "T__8", 
		"T__9", "T__10", "T__11", "T__12", "T__13", "T__14", "T__15", "T__16", 
		"UID", "ID", "Digits", "STRING", "MSTRING", "EscapeSequence", "DIGIT", 
		"LETTER", "WS", "COMMENT", "LINE_COMMENT"
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
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\33\u00c2\b\1\4\2"+
		"\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4"+
		"\13\t\13\4\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\4\22"+
		"\t\22\4\23\t\23\4\24\t\24\4\25\t\25\4\26\t\26\4\27\t\27\4\30\t\30\4\31"+
		"\t\31\4\32\t\32\4\33\t\33\4\34\t\34\4\35\t\35\3\2\3\2\3\3\3\3\3\4\3\4"+
		"\3\5\3\5\3\6\3\6\3\6\3\7\3\7\3\7\3\b\3\b\3\b\3\b\3\b\3\t\3\t\3\t\3\t\3"+
		"\n\3\n\3\13\3\13\3\13\3\f\3\f\3\r\3\r\3\16\3\16\3\17\3\17\3\17\3\17\3"+
		"\17\3\17\3\17\3\17\3\20\3\20\3\21\3\21\3\22\3\22\3\22\3\22\3\23\3\23\7"+
		"\23p\n\23\f\23\16\23s\13\23\3\23\3\23\3\24\3\24\3\24\7\24z\n\24\f\24\16"+
		"\24}\13\24\3\25\6\25\u0080\n\25\r\25\16\25\u0081\3\26\3\26\3\26\7\26\u0087"+
		"\n\26\f\26\16\26\u008a\13\26\3\26\3\26\3\27\3\27\3\27\3\27\3\27\7\27\u0093"+
		"\n\27\f\27\16\27\u0096\13\27\3\27\3\27\3\27\3\27\3\30\3\30\3\30\3\31\3"+
		"\31\3\32\3\32\3\33\6\33\u00a4\n\33\r\33\16\33\u00a5\3\33\3\33\3\34\3\34"+
		"\3\34\3\34\7\34\u00ae\n\34\f\34\16\34\u00b1\13\34\3\34\3\34\3\34\3\34"+
		"\3\34\3\35\3\35\3\35\3\35\7\35\u00bc\n\35\f\35\16\35\u00bf\13\35\3\35"+
		"\3\35\4\u0094\u00af\2\36\3\3\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13\25\f"+
		"\27\r\31\16\33\17\35\20\37\21!\22#\23%\24\'\25)\26+\27-\30/\2\61\2\63"+
		"\2\65\31\67\329\33\3\2\b\5\2\13\f\16\17bb\4\2$$^^\n\2$$))^^ddhhppttvv"+
		"\5\2C\\aac|\5\2\13\f\16\17\"\"\4\2\f\f\17\17\2\u00c8\2\3\3\2\2\2\2\5\3"+
		"\2\2\2\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2\2\2\2\17\3\2\2\2\2"+
		"\21\3\2\2\2\2\23\3\2\2\2\2\25\3\2\2\2\2\27\3\2\2\2\2\31\3\2\2\2\2\33\3"+
		"\2\2\2\2\35\3\2\2\2\2\37\3\2\2\2\2!\3\2\2\2\2#\3\2\2\2\2%\3\2\2\2\2\'"+
		"\3\2\2\2\2)\3\2\2\2\2+\3\2\2\2\2-\3\2\2\2\2\65\3\2\2\2\2\67\3\2\2\2\2"+
		"9\3\2\2\2\3;\3\2\2\2\5=\3\2\2\2\7?\3\2\2\2\tA\3\2\2\2\13C\3\2\2\2\rF\3"+
		"\2\2\2\17I\3\2\2\2\21N\3\2\2\2\23R\3\2\2\2\25T\3\2\2\2\27W\3\2\2\2\31"+
		"Y\3\2\2\2\33[\3\2\2\2\35]\3\2\2\2\37e\3\2\2\2!g\3\2\2\2#i\3\2\2\2%m\3"+
		"\2\2\2\'v\3\2\2\2)\177\3\2\2\2+\u0083\3\2\2\2-\u008d\3\2\2\2/\u009b\3"+
		"\2\2\2\61\u009e\3\2\2\2\63\u00a0\3\2\2\2\65\u00a3\3\2\2\2\67\u00a9\3\2"+
		"\2\29\u00b7\3\2\2\2;<\7<\2\2<\4\3\2\2\2=>\7=\2\2>\6\3\2\2\2?@\7\u0080"+
		"\2\2@\b\3\2\2\2AB\7?\2\2B\n\3\2\2\2CD\7-\2\2DE\7?\2\2E\f\3\2\2\2FG\7/"+
		"\2\2GH\7?\2\2H\16\3\2\2\2IJ\7v\2\2JK\7j\2\2KL\7k\2\2LM\7u\2\2M\20\3\2"+
		"\2\2NO\7c\2\2OP\7t\2\2PQ\7i\2\2Q\22\3\2\2\2RS\7\60\2\2S\24\3\2\2\2TU\7"+
		"]\2\2UV\7_\2\2V\26\3\2\2\2WX\7*\2\2X\30\3\2\2\2YZ\7+\2\2Z\32\3\2\2\2["+
		"\\\7B\2\2\\\34\3\2\2\2]^\7e\2\2^_\7n\2\2_`\7c\2\2`a\7u\2\2ab\7u\2\2bc"+
		"\7Q\2\2cd\7h\2\2d\36\3\2\2\2ef\7&\2\2f \3\2\2\2gh\7A\2\2h\"\3\2\2\2ij"+
		"\7t\2\2jk\7g\2\2kl\7v\2\2l$\3\2\2\2mq\7b\2\2np\n\2\2\2on\3\2\2\2ps\3\2"+
		"\2\2qo\3\2\2\2qr\3\2\2\2rt\3\2\2\2sq\3\2\2\2tu\7b\2\2u&\3\2\2\2v{\5\63"+
		"\32\2wz\5\63\32\2xz\5\61\31\2yw\3\2\2\2yx\3\2\2\2z}\3\2\2\2{y\3\2\2\2"+
		"{|\3\2\2\2|(\3\2\2\2}{\3\2\2\2~\u0080\5\61\31\2\177~\3\2\2\2\u0080\u0081"+
		"\3\2\2\2\u0081\177\3\2\2\2\u0081\u0082\3\2\2\2\u0082*\3\2\2\2\u0083\u0088"+
		"\7$\2\2\u0084\u0087\5/\30\2\u0085\u0087\n\3\2\2\u0086\u0084\3\2\2\2\u0086"+
		"\u0085\3\2\2\2\u0087\u008a\3\2\2\2\u0088\u0086\3\2\2\2\u0088\u0089\3\2"+
		"\2\2\u0089\u008b\3\2\2\2\u008a\u0088\3\2\2\2\u008b\u008c\7$\2\2\u008c"+
		",\3\2\2\2\u008d\u008e\7$\2\2\u008e\u008f\7$\2\2\u008f\u0090\7$\2\2\u0090"+
		"\u0094\3\2\2\2\u0091\u0093\13\2\2\2\u0092\u0091\3\2\2\2\u0093\u0096\3"+
		"\2\2\2\u0094\u0095\3\2\2\2\u0094\u0092\3\2\2\2\u0095\u0097\3\2\2\2\u0096"+
		"\u0094\3\2\2\2\u0097\u0098\7$\2\2\u0098\u0099\7$\2\2\u0099\u009a\7$\2"+
		"\2\u009a.\3\2\2\2\u009b\u009c\7^\2\2\u009c\u009d\t\4\2\2\u009d\60\3\2"+
		"\2\2\u009e\u009f\4\62;\2\u009f\62\3\2\2\2\u00a0\u00a1\t\5\2\2\u00a1\64"+
		"\3\2\2\2\u00a2\u00a4\t\6\2\2\u00a3\u00a2\3\2\2\2\u00a4\u00a5\3\2\2\2\u00a5"+
		"\u00a3\3\2\2\2\u00a5\u00a6\3\2\2\2\u00a6\u00a7\3\2\2\2\u00a7\u00a8\b\33"+
		"\2\2\u00a8\66\3\2\2\2\u00a9\u00aa\7\61\2\2\u00aa\u00ab\7,\2\2\u00ab\u00af"+
		"\3\2\2\2\u00ac\u00ae\13\2\2\2\u00ad\u00ac\3\2\2\2\u00ae\u00b1\3\2\2\2"+
		"\u00af\u00b0\3\2\2\2\u00af\u00ad\3\2\2\2\u00b0\u00b2\3\2\2\2\u00b1\u00af"+
		"\3\2\2\2\u00b2\u00b3\7,\2\2\u00b3\u00b4\7\61\2\2\u00b4\u00b5\3\2\2\2\u00b5"+
		"\u00b6\b\34\3\2\u00b68\3\2\2\2\u00b7\u00b8\7\61\2\2\u00b8\u00b9\7\61\2"+
		"\2\u00b9\u00bd\3\2\2\2\u00ba\u00bc\n\7\2\2\u00bb\u00ba\3\2\2\2\u00bc\u00bf"+
		"\3\2\2\2\u00bd\u00bb\3\2\2\2\u00bd\u00be\3\2\2\2\u00be\u00c0\3\2\2\2\u00bf"+
		"\u00bd\3\2\2\2\u00c0\u00c1\b\35\3\2\u00c1:\3\2\2\2\r\2qy{\u0081\u0086"+
		"\u0088\u0094\u00a5\u00af\u00bd\4\2\3\2\2\4\2";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}