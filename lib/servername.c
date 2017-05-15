/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include "servername.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

const char* get_servername(){
	static char buffer[1<<12];
	const char* un = 0;
	const char* sn = 0;
	buffer[(sizeof buffer)-1] = 0;
	if(!sn) if(un = getenv("SERVER_NAME")) sn = strncpy(buffer,un,(sizeof buffer)-1);
	if(!sn) if(!gethostname(buffer,(sizeof buffer)-1))sn = buffer;
	if(!sn) sn = "localhost";
	return sn;
}

