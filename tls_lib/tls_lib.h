/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

/**
 * Performs initialization for potential STARTTLS use.
 *
 * @return 0 if STARTTLS is not supported. Non-0 otherwise.
 *
 * IMPLEMENTORS:
 * The implementation SHOULD NOT do any expensive works such as loading the
 * certificates. That should be deffered until slamtls_starttls()!
 */
int slamtls_init();


/**
 * This function will replace the function pointers slam_read(), slam_write()
 * and slam_close().
 *
 * @return 0 if STARTTLS is impossible or failed. Non-0 otherwise.
 *
 * IMPLEMENTORS:
 * This function MUST NOT rely on the former slam_read(), slam_write() and
 * slam_close() pointers. Instead, it MUST rely on the filedescriptor 0 or 1,
 * test, wether or not that filedescriptor is a socket and then do STARTTLS.
 * If eighter 0 or 1 is a socket, the implementation SHOULD assume, 0 and 1,
 * refer to the same socket.
 */
int slamtls_starttls();


