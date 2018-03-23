/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * Unix Signal Handling Qt Class
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
 * Under the GNU Affero General Public License version 3 section 7 the
 * copyright holders grant the additional permissions set forth in the
 * ogon Library AGPL Exceptions version 1 as published by
 * Thincast Technologies GmbH.
 *
 * For more information see the file LICENSE in the distribution of this file.
 */

#include <ogon-channels/logging.h>
#include <ogon-channels/qt/unixsignalhandler.h>
#include <QMutex>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

static int sp[2] = { 0, 0 };
static UnixSignalHandler *gInstance = NULL;
static QMutex gMutex;

UnixSignalHandler::UnixSignalHandler() : QObject(NULL) {
	if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
		CWLOG_FTL(CWLOG_TAG("unixsignals"), "error creating socketpair");
		abort();
	}

	socketNotifier = new QSocketNotifier(sp[1], QSocketNotifier::Read, this);
	connect(socketNotifier, SIGNAL(activated(int)), this, SLOT(socketActivated()));
}

UnixSignalHandler::~UnixSignalHandler() {
	delete socketNotifier;
	close(sp[0]);
	close(sp[1]);
}

UnixSignalHandler* UnixSignalHandler::instance() {
	if (!gInstance) {
		gMutex.lock();
		if (!gInstance) {
			gInstance = new UnixSignalHandler();
		}
		gMutex.unlock();
	}
	return gInstance;
}

void UnixSignalHandler::destroy() {
	if (gInstance) {
		gMutex.lock();
		if (gInstance) {
			delete gInstance;
			gInstance = NULL;
		}
		gMutex.unlock();
	}
}

bool UnixSignalHandler::watch(int signum) {
	struct sigaction sa;
	sa.sa_handler = UnixSignalHandler::unixHandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	return (sigaction(signum, &sa, NULL) != 0);
}

void UnixSignalHandler::unixHandler(int signum) {
	char c = signum;
	if (write(sp[0], &c, 1) != 1) {
		char msg[] = "error writing signal to socket\n";
		write(STDERR_FILENO, msg, sizeof(msg));
	}
}

void UnixSignalHandler::socketActivated() {
	char c = 0;
	if (read(sp[1], &c, 1) == 1) {
		emit activated(int(c));
	}
}
