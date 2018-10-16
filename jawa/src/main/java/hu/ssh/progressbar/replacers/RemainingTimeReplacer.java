/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.replacers;

import hu.ssh.progressbar.progress.Progress;
import hu.ssh.progressbar.helpers.HumanTimeFormatter;

public class RemainingTimeReplacer implements Replacer {
	private static final String IDENTIFIER = ":eta";

	@Override
	public final String getReplaceIdentifier() {
		return IDENTIFIER;
	}

	@Override
	public final String getReplacementForProgress(final Progress progress) {
		if (!progress.isRemainingTimeReliable()) {
			return "?";
		}

		return HumanTimeFormatter.formatTime(progress.getRemainingTime());
	}
}
