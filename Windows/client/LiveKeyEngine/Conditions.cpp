/*
* Copyright (c) 2026 WinMagic Corp.
* This file is part of the WinMagic LIT reference project.
* This software is dual-licensed:
*
* 1. GNU Affero General Public License v3.0 (AGPL-3.0)
* 2. Commercial license available from WinMagic Corp.
*
* You may use this file under the terms of the AGPL-3.0 license
* included in the LICENSE file in the root of this repository.
*
* For commercial licensing options, OEM redistribution rights,
* proprietary use, or support agreements, please contact WinMagic.
*/

#include "Conditions.h"

/*
 * Mint phase:
 * Creates (or reconstructs) the LiveKey only when all required mint
 * conditions are satisfied. The mint process verifies the required
 * trust conditions before allowing key creation, making it difficult
 * to produce a valid key outside the approved environment. Trust is
 * established at registration time: the relying party accepts a key
 * that could only exist if the mint conditions were met.
 * For illustration purposes this example returns ERROR_SUCCESS.
 * Production implementations perform actual mint-condition validation
 * and return an appropriate status code when one or more required
 * conditions are not satisfied.
 */
DWORD AreMintConditionsSatisfied()
{
	return ERROR_SUCCESS;
}

/*
 * Exercise phase: Use the existing LiveKey. Runtime policies may restrict
 * usage or erase the key. Recreation requires satisfying the mint
 * conditions again.
 * For illustration purposes this example returns ERROR_SUCCESS.
 * Production implementations perform actual exercise-condition validation
 * and return an appropriate status code when one or more required
 * conditions are not satisfied.
 */
DWORD AreExerciseConditionsSatisfied()
{
	return ERROR_SUCCESS;
}

