/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Spangap fork: gutted. The upstream globals (`JsonDocument _document`,
 * `Bytes _buffer`) are gone — see Utilities/Persistence.h for why. This
 * .cpp stays in the tree only to give the build something to compile under
 * the same name; future cJSON-based persistence will replace it.
 */
