/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * Clipboard Redirection Server Qt Class
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

#ifndef RDPCLIPCHANNELSERVER_H
#define RDPCLIPCHANNELSERVER_H

#include <QApplication>
#include <QString>
#include <QByteArray>
#include <QHash>
#include <QClipboard>
#include <QMimeData>
#include <QQueue>
#include <QTimer>

#include <ogon-channels/qt/rdpchannelserver.h>
#include <ogon-channels/qt/rdpsessionnotification.h>

class RDPClipChannelServer : public RDPChannelServer {
	Q_OBJECT

public:
	RDPClipChannelServer(QApplication *app,
			bool useDelayedRendering, bool usePrimarySelection,
			bool useSessionNotification, QObject *parent = 0);
	virtual ~RDPClipChannelServer();
	virtual bool start();
	virtual bool stop();

	bool isWaitingForFormatDataResponse();
	bool isSelectionOwner();
	bool isClipboardOwner();

	bool sendTextFormatRequest();
	bool sendHtmlFormatRequest();

private:
	typedef QHash<quint32, QString> ClipboardFormats;
	typedef QHashIterator<quint32, QString> ClipboardFormatsIterator;

	virtual bool processReceivedData(RdpStreamBuffer &stream);
	virtual void sessionChange(Status status, quint32 sessionId);

	void setClipboardMimeData(QMimeData *src);

	bool sendCapabilities();
	bool sendMonitorReady();
	bool sendFormatList();
	bool sendFormatDataRequest(quint32 formatId);
	bool sendFormatListResponse(bool responseOk);
	bool sendFormatDataResponse(bool responseOk, const QByteArray &data);
	bool receiveCapabilities(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveTemporaryDirectory(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveFormatListResponse(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveFormatDataRequest(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveFormatDataResponse(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveLongFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s);
	bool receiveShortFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s);

	QClipboard* mClipboard;
	QClipboard::Mode mClipboardMode;
	QMimeData mPeerCache;
	QTimer mClipboardChangedTimer;

	bool mUseSessionNotification;
	bool mUseDelayedRendering;

	quint32 mNumChangedEventsToIgnore;
	bool mOwnershipSupported;
	QQueue<quint32> mPeerRequestQueue;
	quint32 mRequestedFormat;

	bool mInitSequenceCompleted;
	bool mClientCapsReceived;
	bool mClientTemporaryDirectoryReceived;
	QString mClientTemporaryDirectory;
	bool mPeerFormatListResponseOk;

	bool mUseLongFormatNames;
	bool mStreamFileClipEnabled;
	bool mFileClipNoFilePaths;
	bool mCanLockClipData;

	ClipboardFormats mPeerFormats;
	ClipboardFormats mHostFormats;

private slots:
	void clipboardChanged();
	void processClipboardChange();
};

#endif /* RDPCLIPCHANNELSERVER_H */
