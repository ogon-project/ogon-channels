/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * Example server side channel
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

#include <unistd.h>
#include <sys/types.h>
#include <mntent.h>
#include "example-channelserver.h"

ExampleChannelServer::ExampleChannelServer(QCoreApplication *app, QString channelName,
	bool useSessionNotification, bool isDynamic, QObject *parent)
	: RDPChannelServer(WTS_CURRENT_SERVER, WTS_CURRENT_SESSION, channelName, true, parent)
	, mUseSessionNotification(useSessionNotification)
{
	if (!app) {
		CWLOG_FTL(TAG, "fatal: cannot work with null application");
		abort();
	}

	setIsDynamic(isDynamic);

	if (mUseSessionNotification) {
		registerSessionNotification(NotifyForThisSession);
	}

	connect(unixSignalHandler, SIGNAL(activated(int)), this, SLOT(handleUnixSignal(int)));
	unixSignalHandler->watch(SIGHUP);
	unixSignalHandler->watch(SIGINT);
	unixSignalHandler->watch(SIGTERM);

	mMainLock = new QMutex(QMutex::Recursive);
}

ExampleChannelServer::~ExampleChannelServer() {
	unixSignalHandler->destroy();
	stop();
	delete mMainLock;
}

void ExampleChannelServer::handleUnixSignal(int signum) {
	switch(signum) {
		case SIGHUP:
			CWLOG_INF(TAG, "SIGHUP received. terminating ...");
			break;
		case SIGINT:
			CWLOG_INF(TAG, "SIGINT received. terminating ...");
			break;
		case SIGTERM:
			CWLOG_INF(TAG, "SIGTERM received. terminating ...");
			break;
		default:
			CWLOG_WRN(TAG, "ignoring unexpected unix signal %d", signum);
			return;
	}
	qApp->exit(0);
}


bool ExampleChannelServer::processReceivedData(RdpStreamBuffer &stream) {
	CWLOG_VRB(TAG, "%s: stream.remainingLength(): %lu", __FUNCTION__, stream.remainingLength());
	CWLOG_ERR(TAG, "%s: IMPLEMENT ME..", __FUNCTION__);
	return true;
}

void ExampleChannelServer::sessionChange(Status status, quint32 sessionId) {
	if (status == RDPSessionNotification::WtsSessionLogoff) {
		qApp->exit(0);
	} else {
		RDPChannelServer::sessionChange(status, sessionId);
	}
}

bool ExampleChannelServer::start() {
	CWLOG_INF(TAG, "starting example channel server");

	if (!isInitOk() || isStarted() || !RDPChannelServer::start()) {
		return false;
	}

	return true;
}

bool ExampleChannelServer::stop() {
	if (!isStarted()) {
		return false;
	}

	CWLOG_INF(TAG, "stopping example channel server");

	RDPChannelServer::stop();

	QMutexLocker locker(mMainLock);

	return true;
}
