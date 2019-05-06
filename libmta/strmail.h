/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once
#include "common.h"

/*
 * Converts "User Name <user.name@mydomain.net>" into "user.name@mydomain.net". In-Place.
 *
 * PCRE version: s/.* <(.*)>/\1/;
 */
void mta_unwrap_mail(mta_sds mail);


/*
 * Verifies that the submitted mail address is in either of the following forms:
 *   User Name <local-part@domain>
 *   local-part@domain
 *
 * returns 0 if check failed, non-0 otherwise.
 */
int mta_verify_mail(mta_sds mail);

