/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic LIT reference project.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of the WinMagic Inc.
* Commercial License, which can be found at https://winmagic.com/en/legal/commercial_license/
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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

