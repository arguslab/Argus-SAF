/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar;


/**
 * Defines the main interfaces to work with a progressbar.
 *
 * @author KARASZI István (github@spam.raszi.hu)
 */
public interface ProgressBar {
	/**
	 * Starts the progress bar.
	 */
	void start();

	/**
	 * Tick one step with the progressbar.
	 */
	void tickOne();

	/**
	 * Tick the specified steps with the progressbar.
	 *
	 * @param steps
	 *            the specified steps
	 */
	void tick(long steps);

	/**
	 * Refresh the progressbar.
	 */
	void refresh();

	/**
	 * Finish the progressbar.
	 */
	void complete();

	/**
	 * Changes the total steps of the actual ProgressBar.
	 * 
	 * @param totalSteps
	 *            the new total steps
	 * @return a progress bar with the desired configuration
	 */
	ProgressBar withTotalSteps(int totalSteps);
}