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

#ifndef EXAMPLECHANNELSERVER_H
#define EXAMPLECHANNELSERVER_H

#include <QThread>
#include <QMutex>
#include <QMutexLocker>
#include <QWaitCondition>
#include <QApplication>
#include <QString>
#include <QByteArray>
#include <QList>
#include <QDir>
#include <QTime>
#include <QDateTime>

#include <ogon-channels/qt/rdpchannelserver.h>
#include <ogon-channels/qt/rdpsessionnotification.h>
#include <ogon-channels/qt/unixsignalhandler.h>
#include <ogon-channels/logging.h>

#define TAG CWLOG_TAG("example") 

class ExampleChannelServer : public RDPChannelServer {
	Q_OBJECT

public:
	ExampleChannelServer(QCoreApplication *app, QString channelName, bool useSessionNotification, bool isDynamic, QObject *parent = 0);
	virtual ~ExampleChannelServer();
	virtual bool start();
	virtual bool stop();
	virtual bool processReceivedData(RdpStreamBuffer&);
	virtual void sessionChange(Status status, quint32 sessionId);

private:
	QMutex* mMainLock;
	bool mUseSessionNotification;

private slots:
	  void handleUnixSignal(int signum);
};

#endif /* EXAMPLECHANNELSERVER_H */
