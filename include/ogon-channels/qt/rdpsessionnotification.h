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

#ifndef RDPSESSIONNOTIFICATION_H
#define RDPSESSIONNOTIFICATION_H

#include <QtGlobal>
#include <QObject>
#include <QString>

class RDPSessionNotification : public QObject
{
	Q_OBJECT

public:
	RDPSessionNotification(QObject *parent = 0);
	virtual ~RDPSessionNotification();

	enum Status {
		WtsConsoleConnect = 0x1,
		WtsConsoleDisconnect = 0x2,
		WtsRemoteConnect = 0x3,
		WtsRemoteDisconnect = 0x4,
		WtsSessionLogon = 0x5,
		WtsSessionLogoff = 0x6,
		WtsSessionLock = 0x7,
		WtsSessionUnlock = 0x8,
		WtsSessionRemoteControl = 0x9,
		WtsSessionCreate = 0xA,
		WtsSessionTerminate = 0xB,
	};

	enum Mode {
		NotifyForThisSession = 0x0,
		NotifyForAllSessions = 0x1,
	};

	virtual void sessionChange(Status status, quint32 sessionId);
	bool registerSessionNotification(Mode mode);
	bool unRegisterSessionNotification();
	const char *statusString(Status status);

	quint32 getSessionId();

private slots:
	void sessionChangeInternal(uint status, uint id);

private:
	bool mIsRegistered;
	Mode mRegisteredMode;
	quint32 mSessionId;

	QString mDbusHost;
	QString mDbusPath;
	QString mDbusName;
};

#endif /* RDPSESSIONNOTIFICATION_H */
