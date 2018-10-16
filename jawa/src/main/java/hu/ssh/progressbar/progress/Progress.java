/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.progress;

public class Progress {
	private static final int MINIMAL_ELAPSED = 100;

	private final long totalSteps;
	private final long actualSteps;
	private final long elapsedTime;

	public Progress(final long totalSteps, final long actualSteps, final long elapsedTime) {
		this.totalSteps = totalSteps;
		this.actualSteps = actualSteps;
		this.elapsedTime = elapsedTime;
	}

	public final long getTotalSteps() {
		return totalSteps;
	}

	public final long getActualSteps() {
		return actualSteps;
	}

	public final long getElapsedTime() {
		return elapsedTime;
	}

	public final float getPercentage() {
		return (float) actualSteps / totalSteps;
	}

	public final long getRemainingTime() {
		return getTotalTime() - elapsedTime;
	}

	public final long getTotalTime() {
		return (long) (elapsedTime / getPercentage());
	}

	public final boolean isRemainingTimeReliable() {
		return elapsedTime > MINIMAL_ELAPSED;
	}
}