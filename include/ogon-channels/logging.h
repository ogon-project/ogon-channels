/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * FreeRDP WLog helpers
 *
 * Copyright (c) 2016-2018 Thincast Technologies GmbH
 *
 * Authors:
 * Norbert Federa <norbert.federa@thincast.com>
 *
 * This file may be used under the terms of the GNU Affero General
 * Public License version 3 as published by the Free Software Foundation
 * and appearing in the file LICENSE-AGPL included in the distribution
 * of this file.
 *
 * Under the GNU Affero General Public License version 3 section 7 the
 * copyright holders grant the additional permissions set forth in the
 * ogon Core AGPL Exceptions version 1 as published by
 * Thincast Technologies GmbH.
 *
 * Under the GNU Affero General Public License version 3 section 7 the
 * copyright holders grant the additional permissions set forth in the
 * ogon Library AGPL Exceptions version 1 as published by
 * Thincast Technologies GmbH.
 *
 * For more information see the file LICENSE in the distribution of this file.
 */

#ifndef OGON_CHANNELS_LOGGING_H
#define OGON_CHANNELS_LOGGING_H

#include <winpr/wlog.h>

#define CWLOG_TAG(tag) "com.ogon.channels." tag

static inline unsigned _ogon_sid() {
	static unsigned i = 0;
	if (i == 0) {
		const char* e = getenv("OGON_SID");
		i = e ? atoi(e) : 0;
	}
	return i;
}

#define QCSTR(QSTR) QSTR.toUtf8().constData()

#define CWLOG_SID_PREFIX "[s%u] "

#define CWLOG_DBG(TAG, FMT, ...) WLog_DBG(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)
#define CWLOG_INF(TAG, FMT, ...) WLog_INFO(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)
#define CWLOG_ERR(TAG, FMT, ...) WLog_ERR(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)
#define CWLOG_WRN(TAG, FMT, ...) WLog_WARN(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)
#define CWLOG_VRB(TAG, FMT, ...) WLog_VRB(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)
#define CWLOG_FTL(TAG, FMT, ...) WLog_FATAL(TAG, CWLOG_SID_PREFIX FMT, _ogon_sid(), ## __VA_ARGS__)

#endif /* OGON_CHANNELS_LOGGING_H */
