/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * X11 Clipboard Redirection Server
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

#include <QApplication>
#include <QStringList>
#include "rdpx11clipchannelserver.h"

#include <ogon-channels/logging.h>
#define TAG CWLOG_TAG("rdpclip")

QString primaryParam("--primary");
QString clipboardParam("--clipboard");
QString logParam("--log=");

void usage() {
	fprintf(stderr, "Usage: %s [%s | %s] [%sconsole|syslog|journald]\n",
			QCSTR(qApp->arguments().at(0)),
			QCSTR(clipboardParam),
			QCSTR(primaryParam),
                        QCSTR(logParam));
	fprintf(stderr, "If neither %s nor %s is specified the default mode is primary.\n",
			QCSTR(clipboardParam),
			QCSTR(primaryParam));
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
	QApplication app(argc, argv);
	bool delayedRendering = true;
	unsigned mode = 0;
	bool usePrimarySelection = true;

	unsigned wlogAppenderType = WLOG_APPENDER_CONSOLE;

	for (int i = 1; i < app.arguments().size(); i++) {
		QString arg(app.arguments().at(i));
		if (arg == primaryParam) {
			if (mode) {
				usage();
				return 1;
			}
			mode = 1;
		}
		else if (arg == clipboardParam) {
			if (mode) {
				usage();
				return 1;
			}
			mode = 2;
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

	if (mode == 2) {
		usePrimarySelection = false;
	}

	RdpX11ClipChannelServer rdpclip(&app, delayedRendering, usePrimarySelection);

	if (!rdpclip.isInitOk()) {
		CWLOG_ERR(TAG, "Error initializing rdpclip channel server");
		return 1;
	}

	if (!rdpclip.lockApplicationInstance()) {
		CWLOG_INF(TAG, "Sorry, another instance of the rdpclip channel is running in this RDP session");
		return 1;
	}

	if (!rdpclip.start()) {
		/* Don't terminate app on error ! */
	}

	return app.exec();
}
