/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * D-Bus based RDP Session Notification Qt Class
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

#include <ogon-channels/qt/rdpsessionnotification.h>
#include <ogon-channels/logging.h>

#include <QtDBus/QtDBus>

#include <winpr/wtsapi.h>

#define SNDBUSHOST "ogon.SessionManager.session.notification"
#define SNDBUSPATH "/ogon/SessionManager/session/notification"
#define SNDBUSNAME "SessionNotification"

#define TAG CWLOG_TAG("notification")

RDPSessionNotification::RDPSessionNotification(QObject *parent)
	: QObject(parent)
	, mIsRegistered(false)
{

}

RDPSessionNotification::~RDPSessionNotification() {
	if (mIsRegistered) {
		unRegisterSessionNotification();
	}
}

const char* RDPSessionNotification::statusString(Status code) {
	switch(code) {
		case WtsConsoleConnect:
			return "WTS_CONSOLE_CONNECT";
		case WtsConsoleDisconnect:
			return "WTS_CONSOLE_DISCONNECT";
		case WtsRemoteConnect:
			return "WTS_REMOTE_CONNECT";
		case WtsRemoteDisconnect:
			return "WTS_REMOTE_DISCONNECT";
		case WtsSessionLogon:
			return "WTS_SESSION_LOGON";
		case WtsSessionLogoff:
			return "WTS_SESSION_LOGOFF";
		case WtsSessionLock:
			return "WTS_SESSION_LOCK";
		case WtsSessionUnlock:
			return "WTS_SESSION_UNLOCK";
		case WtsSessionRemoteControl:
			return "WTS_SESSION_REMOTE_CONTROL";
		case WtsSessionCreate:
			return "WTS_SESSION_CREATE";
		case WtsSessionTerminate:
			return "WTS_SESSION_TERMINATE";
	}

	return "INVALID STATUS CODE";
}

quint32 RDPSessionNotification::getSessionId()
{
	if (mIsRegistered) {
		return mSessionId;
	}
	return 0;
}

void RDPSessionNotification::sessionChange(Status status, quint32 sessionId) {
	Q_UNUSED(status);
	Q_UNUSED(sessionId);
	//CWLOG_VRB("status changed to %s", statusString(status));
}

void RDPSessionNotification::sessionChangeInternal(uint code, uint id) {
	if (mRegisteredMode == NotifyForThisSession && id != mSessionId) {
		return;
	}

	if (code >= WtsConsoleConnect && code <= WtsSessionTerminate) {
		sessionChange((Status)code, id);
	}
}

bool RDPSessionNotification::registerSessionNotification(Mode mode) {
	LPWSTR buffer;
	DWORD size;
	ULONG id;

	if (mIsRegistered) {
		CWLOG_ERR(TAG, "session notification already registered");
		return false;
	}

	if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
		WTS_CURRENT_SESSION, WTSSessionId, &buffer, &size))
	{
		CWLOG_ERR(TAG, "failed to query current session id");
		return false;
	}

	id = *(ULONG *)buffer;
	WTSFreeMemory(buffer);

	mSessionId = id;

	mRegisteredMode = mode;

	if (!QDBusConnection::systemBus().isConnected()) {
		CWLOG_ERR(TAG, "error, system dbus is not connected");
		return false;
	}

	mIsRegistered = QDBusConnection::systemBus().connect(
		SNDBUSHOST, SNDBUSPATH, SNDBUSHOST, SNDBUSNAME,
		this, SLOT(sessionChangeInternal(uint, uint)));

	if (!mIsRegistered) {
		CWLOG_ERR(TAG, "dbus slot connection failed");
	}

	return mIsRegistered;
}

bool RDPSessionNotification::unRegisterSessionNotification() {
	if (!mIsRegistered) {
		CWLOG_ERR(TAG, "error, session notification is not registered");
		return false;
	}

	mIsRegistered = !QDBusConnection::systemBus().disconnect(
                SNDBUSHOST, SNDBUSPATH, SNDBUSHOST, SNDBUSNAME,
                this, SLOT(sessionChangeInternal(uint, uint)));

	if (mIsRegistered) {
		CWLOG_ERR(TAG, "dbus slot disconnection failed");
		return false;
	}

	return !mIsRegistered;
}
