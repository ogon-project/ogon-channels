/**
 * RDP Virtual Channel Servers
 * Example server side virtual channel
 * 
 * Copyright (c) 2014-2018 Thincast Technologies GmbH
 *
 * Authors:
 * Bernhard Miklautz <bernhard.miklautz@thincast.com>
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

#include "example-channelserver.h"

QString logParam("--log=");
QString dynamicParam("--dynamic");
QString nameParam("--name=");

void usage() {
	fprintf(stderr, "Usage: %s [%s] [%s] [%ssyslog|journald|console]\n\n",
			QCSTR(qApp->arguments().at(0)),
			QCSTR(nameParam),
			QCSTR(dynamicParam),
			QCSTR(logParam));

	fprintf(stderr, "Use --dynamic to start a dynamic channel\n");
	fprintf(stderr, "Use --name to specify the channel name to use (default EXAMPLE)\n");

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
	bool dynamicChannel = false;
	QString channelName("EXAMPLE");

	unsigned wlogAppenderType = WLOG_APPENDER_CONSOLE;


	for (int i = 1; i < app.arguments().size(); i++) {
		QString arg(app.arguments().at(i));
		if (arg.startsWith(logParam)) {
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
		else if (arg.startsWith(dynamicParam)) {
			dynamicChannel = true;
		}
		else if (arg.startsWith(nameParam)) {
			QString value = arg.mid(nameParam.size());
			if (value.size()) {
				channelName = value;
			}
		}
		else {
			usage();
			return 1;
		}
	}

	initializeLogging(wlogAppenderType);

	CWLOG_INF(TAG, "example-channel launching at %s", QCSTR(QDateTime::currentDateTime().toString()));


	ExampleChannelServer example(&app, channelName, true, dynamicChannel);

	if (!example.isInitOk()) {
		CWLOG_ERR(TAG, "error initializing example channel server");
		return 1;
	}

	if (!example.lockApplicationInstance()) {
		CWLOG_ERR(TAG, "Sorry, another instance of the example channel is running in this session");
		return 1;
	}

	if (!example.start()) {
		return 1;
	}

	return app.exec();
}
