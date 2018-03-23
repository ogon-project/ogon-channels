/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * File System Virtual Channel Server
 *
 * Copyright (c) 2014-2018 Thincast Technologies GmbH
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
 * For more information see the file LICENSE in the distribution of this file.
 */

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <sys/syscall.h>
#include <unistd.h>
#include <winpr/wlog.h>

#include "rdpdrchannelserver.h"

QString mountPointParam("--mountpointrule=");
QString timeoutParam("--timeout=");
QString logParam("--log=");

void usage() {
	fprintf(stderr, "Usage: %s [%srule] [%sms] [%ssyslog|journald|console]\n\n",
			QCSTR(qApp->arguments().at(0)),
			QCSTR(mountPointParam),
			QCSTR(timeoutParam),
			QCSTR(logParam));

	fprintf(stderr, "The mountpoint rule string supports the following macros:\n");
	fprintf(stderr, "{HOME}       : user's home directory\n");
	fprintf(stderr, "{CLIENTNAME} : RDP client name\n");
	fprintf(stderr, "{SESSIONID}  : the ogon RDP session id\n");
	fprintf(stderr, "{DEVICENAME} : the name of the remotedevice name (e.g. X:)\n\n");

	fprintf(stderr, "The default mountpoint rule is: \"{HOME}/rdpfiles/{CLIENTNAME}/{SESSIONID}/{DEVICENAME}/\"\n");
}

void initializeLogging(unsigned wlogAppenderType) {
	wLog *wlog_root;
	wLogLayout *layout;

	WLog_Init();

	if (!(wlog_root = WLog_GetRoot())) {
		fprintf(stderr, "Failed to get the logger root\n");
		goto fail;
	}

	if (!WLog_SetLogAppenderType(wlog_root, wlogAppenderType)) {
		fprintf(stderr, "Failed to initialize the logger appender type\n");
		goto fail;
	}

	if (!(layout = WLog_GetLogLayout(wlog_root))) {
		fprintf(stderr, "Failed to get the logger layout\n");
		goto fail;
	}

	//if (!WLog_Layout_SetPrefixFormat(wlog_root, layout, "[%hr:%mi:%se:%ml] [%pid:%tid] [%lv] | ")) {
	if (!WLog_Layout_SetPrefixFormat(wlog_root, layout, "[%yr.%mo.%dy %hr:%mi:%se:%ml] [%pid:%tid] [%lv:%mn] [%fl|%fn|%ln] - ")) {
		fprintf(stderr, "Failed to set the logger output format\n");
		goto fail;
	}

	return;
fail:
	exit(1);
}

int main(int argc, char **argv) {
	QCoreApplication app(argc, argv);
	QString mountPointRule;
	quint32 responseTimeout = 0;

	unsigned wlogAppenderType = WLOG_APPENDER_CONSOLE;


	for (int i = 1; i < app.arguments().size(); i++) {
		QString arg(app.arguments().at(i));
		if (arg.startsWith(mountPointParam)) {
			QString value = arg.mid(mountPointParam.size());
			if (value.isEmpty()) {
				usage();
				return 1;
			}
			mountPointRule = value;
		}
		else if (arg.startsWith(timeoutParam)) {
			quint32 value = arg.mid(timeoutParam.size()).toUInt();
			if (value == 0) {
				usage();
				return 1;
			}
			responseTimeout = value;
		}
		else if (arg.startsWith(logParam)) {
			QString value = arg.mid(logParam.size());
			if (value == "syslog") {
				wlogAppenderType = WLOG_APPENDER_SYSLOG;
			}
			else if (value == "journald") {
				wlogAppenderType = WLOG_APPENDER_JOURNALD;
			}
			else if (value != "console") {
				fprintf(stderr, "error, invalid logging backend specified\n");
				usage();
                                return 1;
			}
		}
		else {
			usage();
			return 1;
		}
	}

	initializeLogging(wlogAppenderType);

	CWLOG_INF(TAG, "rdpdr launching at %s", QCSTR(QDateTime::currentDateTime().toString()));


	RDPDrChannelServer rdpdr(&app, true);

	if (!rdpdr.isInitOk()) {
		CWLOG_ERR(TAG, "error initializing rdpdr channel server");
		return 1;
	}

	if (!rdpdr.lockApplicationInstance()) {
		CWLOG_ERR(TAG, "Sorry, another instance of the rdpdr channel is running in this session");
		return 1;
	}

	if (!mountPointRule.isEmpty()) {
		rdpdr.setMountPointRule(mountPointRule);
	}

	if (responseTimeout) {
		rdpdr.setResponseTimeout(responseTimeout);
	}

	if (!rdpdr.start()) {
		return 1;
	}

	return app.exec();
}
