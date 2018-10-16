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
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link SafsuParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface SafsuVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link SafsuParser#summaryFile}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummaryFile(SafsuParser.SummaryFileContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#defaultType}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDefaultType(SafsuParser.DefaultTypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#summary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummary(SafsuParser.SummaryContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#signature}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSignature(SafsuParser.SignatureContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#suRule}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSuRule(SafsuParser.SuRuleContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#clearRule}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitClearRule(SafsuParser.ClearRuleContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#binaryRule}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitBinaryRule(SafsuParser.BinaryRuleContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#ops}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitOps(SafsuParser.OpsContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#lhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLhs(SafsuParser.LhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#rhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRhs(SafsuParser.RhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#suThis}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSuThis(SafsuParser.SuThisContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#arg}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArg(SafsuParser.ArgContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#global}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGlobal(SafsuParser.GlobalContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#heap}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitHeap(SafsuParser.HeapContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#heapAccess}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitHeapAccess(SafsuParser.HeapAccessContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#fieldAccess}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitFieldAccess(SafsuParser.FieldAccessContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#arrayAccess}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArrayAccess(SafsuParser.ArrayAccessContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#instance}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInstance(SafsuParser.InstanceContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#classOf}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitClassOf(SafsuParser.ClassOfContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#type}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitType(SafsuParser.TypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#javaType}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitJavaType(SafsuParser.JavaTypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#innerType}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitInnerType(SafsuParser.InnerTypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#unknown}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitUnknown(SafsuParser.UnknownContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#stringLit}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStringLit(SafsuParser.StringLitContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#ret}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRet(SafsuParser.RetContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#location}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLocation(SafsuParser.LocationContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#virtualLocation}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitVirtualLocation(SafsuParser.VirtualLocationContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#concreteLocation}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitConcreteLocation(SafsuParser.ConcreteLocationContext ctx);
}