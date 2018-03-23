/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * Generic Channel Server Qt Class
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

#ifndef RDPCHANNELSERVER_H
#define RDPCHANNELSERVER_H

#include <QString>
#include <QSocketNotifier>
#include <QByteArray>

#include <winpr/wtsapi.h>

#include <ogon-channels/qt/rdpsessionnotification.h>
#include <ogon-channels/qt/rdpstreambuffer.h>

class RDPChannelServer : public RDPSessionNotification {
	Q_OBJECT

public:
	RDPChannelServer(HANDLE serverHandle, quint32 sessionId, const QString &channelName, bool showProtocol, QObject *parent = 0);
	virtual ~RDPChannelServer();

	virtual bool isInitOk();
	virtual bool isStarted();

	virtual bool start();
	virtual bool stop();

	bool lockApplicationInstance();

	qint64 writeData(const char *data, quint32 maxSize);
	qint64 writeData(const RdpStreamBuffer &stream, quint32 maxSize=0);
	qint64 readData(char *data, quint32 maxSize);

	virtual bool processReceivedData(RdpStreamBuffer &stream) = 0;
	virtual void sessionChange(Status status, quint32 sessionId);

	void setIsDynamic(bool dynamic);
	bool getIsDynamic();

private slots:
	void channelReadReady();

private:
	HANDLE mServerHandle;
	quint32 mSessionId;
	QString mChannelName;
	bool mShowProtocol;
	QSocketNotifier *mSocketNotifier;
	bool mInitOk;
	HANDLE mChannelHandle;
	HANDLE mChannelFileHandle;
	int mChannelFileDescriptor;
	bool mStarted;
	bool mLastChunk;
	quint32 mBytesRequired;
	quint32 mDataLength;
	bool mResetStream;
	RdpStreamBuffer mStream;
	bool mIsDynamic;
};

#endif /* RDPCHANNELSERVER_H */
