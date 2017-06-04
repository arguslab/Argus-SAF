// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.summary/src/main/java/org/argus/summary/grammar/safsu.g4 by ANTLR 4.7
package org.argus.summary.grammar;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link safsuParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface safsuVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link safsuParser#summaryFile}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummaryFile(safsuParser.SummaryFileContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#summary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummary(safsuParser.SummaryContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#signature}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSignature(safsuParser.SignatureContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#suRule}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSuRule(safsuParser.SuRuleContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#lhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLhs(safsuParser.LhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#rhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRhs(safsuParser.RhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#arg}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArg(safsuParser.ArgContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#field}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitField(safsuParser.FieldContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#global}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGlobal(safsuParser.GlobalContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#type}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitType(safsuParser.TypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#ret}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRet(safsuParser.RetContext ctx);
	/**
	 * Visit a parse tree produced by {@link safsuParser#location}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLocation(safsuParser.LocationContext ctx);
}