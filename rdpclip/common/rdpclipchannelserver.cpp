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

#include <QApplication>
#include <QMimeData>
#include <QStringList>
#include <ogon-channels/qt/rdpclipchannelserver.h>

#include <ogon-channels/logging.h>
#define TAG CWLOG_TAG("rdpclipsrv")

/**
 * Official protocol specification:
 * MS-RDPECLIP Remote Desktop Protocol: Clipboard Virtual Channel Extension
 * http://msdn.microsoft.com/en-us/library/cc241066.aspx
 */

#define CLIPRDR_HEADER_LENGTH              0x0008

#define CB_MONITOR_READY                   0x0001
#define CB_FORMAT_LIST                     0x0002
#define CB_FORMAT_LIST_RESPONSE            0x0003
#define CB_FORMAT_DATA_REQUEST             0x0004
#define CB_FORMAT_DATA_RESPONSE            0x0005
#define CB_TEMP_DIRECTORY                  0x0006
#define CB_CLIP_CAPS                       0x0007
#define CB_FILECONTENTS_REQUEST            0x0008
#define CB_FILECONTENTS_RESPONSE           0x0009
#define CB_LOCK_CLIPDATA                   0x000A
#define CB_UNLOCK_CLIPDATA                 0x000B

#define CB_CAPSTYPE_GENERAL                0x0001
#define CB_CAPSTYPE_GENERAL_LEN            0x000C

#define CB_CAPS_VERSION_1                  0x0001
#define CB_CAPS_VERSION_2                  0x0002

#define CB_USE_LONG_FORMAT_NAMES           0x0002
#define CB_STREAM_FILECLIP_ENABLED         0x0004
#define CB_FILECLIP_NO_FILE_PATHS          0x0008
#define CB_CAN_LOCK_CLIPDATA               0x0010

#define CB_RESPONSE_OK                     0x0001
#define CB_RESPONSE_FAIL                   0x0002

#ifndef CF_TEXT
#define CF_TEXT                            0x0001
#endif // CF_TEXT

#ifndef CF_UNICODETEXT
#define CF_UNICODETEXT                     0x000D
#endif // CF_UNICODETEXT

#ifndef CF_PRIVATEFIRST
#define CF_PRIVATEFIRST                    0x0200
#endif // CF_PRIVATEFIRST


RDPClipChannelServer::RDPClipChannelServer(QApplication *app,
	bool useDelayedRendering, bool usePrimarySelection,
	bool useSessionNotification, QObject *parent)
	: RDPChannelServer(WTS_CURRENT_SERVER, WTS_CURRENT_SESSION, "CLIPRDR", true, parent)
	, mClipboardMode(usePrimarySelection ? QClipboard::Selection : QClipboard::Clipboard)
	, mUseSessionNotification(useSessionNotification)
	, mUseDelayedRendering(useDelayedRendering)
{
	if (!app) {
		CWLOG_FTL(TAG, "error: cannot work with null application");
		abort();
		return;
	}
	if (!app->clipboard()) {
		CWLOG_FTL(TAG, "error: cannot work with null clipboard");
		abort();
		return;
	}

	mClipboard = app->clipboard();

	if (!mClipboard->supportsSelection() && mClipboardMode == QClipboard::Selection) {
		CWLOG_WRN(TAG, "warning: requested selections mode is not supported, switching to clipboard mode");
		mClipboardMode = QClipboard::Clipboard;
	}

	CWLOG_DBG(TAG, "active selection mode: %s", 
		mClipboardMode == QClipboard::Selection ? "primary (mouse seletions)" : "clipboard (edit -> copy|paste)");

	if (app->platformName() == "xcb") {
		mOwnershipSupported = true;
	} else if (app->platformName() == "windows") {
		mOwnershipSupported = true;
	} else if (app->platformName() == "ogon") {
		mOwnershipSupported = false;
	} else {
		CWLOG_DBG(TAG, "testing ownership support for experimental platform %s", QCSTR(app->platformName()));
		/* is there a better way how to check presence of ownership concept ? */
		mClipboard->setText("");
		mOwnershipSupported = mClipboard->ownsClipboard();
		mClipboard->clear();
	}
	CWLOG_DBG(TAG, "clipboard ownership supported: %d", mOwnershipSupported);

	if (mUseSessionNotification) {
		registerSessionNotification(NotifyForThisSession);
	}

	mClipboardChangedTimer.setSingleShot(true);
	connect(&mClipboardChangedTimer, SIGNAL(timeout()), this, SLOT(processClipboardChange()));

	if (mClipboardMode == QClipboard::Selection) {
		connect(mClipboard, SIGNAL(selectionChanged()), this, SLOT(clipboardChanged()));
	} else {
		connect(mClipboard, SIGNAL(dataChanged()), this, SLOT(clipboardChanged()));
	}
}

RDPClipChannelServer::~RDPClipChannelServer() {
	stop();
}

void RDPClipChannelServer::clipboardChanged() {
	/*
	 * if the platform's clipboard does not support the ownership
	 * concept we need to find out if one of our own set operations
	 * might have triggered the signal. for now we simply use a counter.
	 * if that turns out to be too unreliable we will have to find a more
	 * stable solution
	 */
	if (!mOwnershipSupported && mNumChangedEventsToIgnore > 0) {
		mNumChangedEventsToIgnore--;
		CWLOG_DBG(TAG, "ignoring self-triggered clipboardChanged signal");
		return;
	}

	if (!isStarted()) {
		return;
	}

	//CWLOG_DBG(TAG, "clipboard data change detected");

	if (mClipboardMode == QClipboard::Selection) {
		/*
		 * Some applications (e.g. gedit) emit massive amounts of change
		 * notifications during mouse text selection and not just a single
		 * one after realeasing the mouse. We try to minimize the channel
		 * load by (re)setting a singleshot timer.
		 */
		mClipboardChangedTimer.start(200);
		return;
	}

	processClipboardChange();
}

void RDPClipChannelServer::processClipboardChange() {
	if (!isStarted()) {
		return;
	}

	switch(mClipboardMode) {
		case QClipboard::Clipboard:
			if (mOwnershipSupported && mClipboard->ownsClipboard()) {
				return;
			}
			break;
		case QClipboard::Selection:
			if (mOwnershipSupported && mClipboard->ownsSelection()) {
				return;
			}
			break;
		default:
			return;
	}

	CWLOG_DBG(TAG, "processing clipboard data change");

	mHostFormats.clear();

	const QMimeData *mime = mClipboard->mimeData(mClipboardMode);

	if (!mime) {
		return;
	}

	int numCustomFormats = 0;

	if (mime->hasText()) {
		mHostFormats[CF_TEXT] = ""; /* must not have a name */
		mHostFormats[CF_UNICODETEXT] = ""; /* must not have a name */
	}

	if (mime->hasHtml()) {
		mHostFormats[CF_PRIVATEFIRST + numCustomFormats++] = "HTML Format";
	}

	sendFormatList();

	return;
}

bool RDPClipChannelServer::isWaitingForFormatDataResponse() {
	return mRequestedFormat > 0;
}

bool RDPClipChannelServer::isSelectionOwner() {
	return mClipboard->ownsSelection();
}

bool RDPClipChannelServer::isClipboardOwner() {
	return mClipboard->ownsClipboard();
}

void RDPClipChannelServer::setClipboardMimeData(QMimeData *src) {
	if (!mOwnershipSupported) {
		mNumChangedEventsToIgnore++;
	}
	mClipboard->setMimeData(src, mClipboardMode);
}

bool RDPClipChannelServer::sendTextFormatRequest() {
	if (!mUseDelayedRendering) {
		CWLOG_ERR(TAG, "error: %s may only be used with delayed rendering", __FUNCTION__);
		return false;
	}

	quint32 formatId = 0;

	if (mPeerFormats.contains(CF_UNICODETEXT)) {
		formatId = CF_UNICODETEXT;
	} else if(mPeerFormats.contains(CF_TEXT)) {
		formatId = CF_TEXT;
	}

	if (formatId == 0) {
		CWLOG_WRN(TAG, "warning: peer did not announce a text format, request canceled");
		return true;
	}

	if (mPeerCache.hasText()) {
		return true;
	}

	((QMimeData *)mClipboard->mimeData(mClipboardMode))->setText("");

	return sendFormatDataRequest(formatId);
}

bool RDPClipChannelServer::sendHtmlFormatRequest() {
	if (!mUseDelayedRendering) {
		CWLOG_ERR(TAG, "error: %s may only be used with delayed rendering", __FUNCTION__);
		return false;
	}

	quint32 formatId = 0;

	ClipboardFormatsIterator i(mPeerFormats);
	while (i.hasNext()) {
		i.next();
		if (i.value() == "HTML Format") {
			formatId = i.key();
			break;
		}
	}

	if (formatId == 0) {
		CWLOG_WRN(TAG, "warning: peer did not announce html format, request canceled");
		return true;
	}

	if (mPeerCache.hasHtml()) {
		return true;
	}

	((QMimeData *)mClipboard->mimeData(mClipboardMode))->setHtml("");

	return sendFormatDataRequest(formatId);
}

bool RDPClipChannelServer::processReceivedData(RdpStreamBuffer &stream) {
	bool result = true;

	if (stream.remainingLength() < CLIPRDR_HEADER_LENGTH) {
		CWLOG_ERR(TAG, "error: invalid clipboard pdu length");
		return false;
	}

	/**
	 * MS-RDPECLIP 2.2.1 Clipboard PDU Header (CLIPRDR_HEADER):
	 * http://msdn.microsoft.com/en-us/library/cc241097.aspx
	 *
	 * Note: dataLen specifies the size, in bytes, of the data which follows
	 * the Clipboard PDU Header
	 */

	quint16 msgType;
	quint16 msgFlags;
	quint32 dataLen;

	stream >> msgType; /* CLIP_PDU_HEADER msgType (2 bytes) */
	stream >> msgFlags; /* CLIP_PDU_HEADER msgFlags (2 bytes) */
	stream >> dataLen; /* CLIP_PDU_HEADER dataLen (4 bytes) */

	if (stream.remainingLength() < dataLen) {
		CWLOG_DBG(TAG, "error: header length exceeds data length");
		return false;
	}

	if (stream.remainingLength() > dataLen) {
		/* ignore padding data */
		stream.sealLength(stream.length() - (stream.remainingLength()-dataLen));
	}

	//CWLOG_DBG(TAG, "receiving pdu type: 0x%04X flags: 0x%04X length: %d",  msgType, msgFlags, dataLen);

	switch (msgType) {
		case CB_CLIP_CAPS:
			result = receiveCapabilities(msgFlags, dataLen, stream);
			break;

		case CB_TEMP_DIRECTORY:
			result = receiveTemporaryDirectory(msgFlags, dataLen, stream);
			break;

		case CB_FORMAT_LIST:
			result = receiveFormatList(msgFlags, dataLen, stream);
			break;

		case CB_FORMAT_LIST_RESPONSE:
			result = receiveFormatListResponse(msgFlags, dataLen, stream);
			break;

		case CB_FORMAT_DATA_REQUEST:
			result = receiveFormatDataRequest(msgFlags, dataLen, stream);
			break;

		case CB_FORMAT_DATA_RESPONSE:
			result = receiveFormatDataResponse(msgFlags, dataLen, stream);
			break;

		case CB_LOCK_CLIPDATA:
		case CB_UNLOCK_CLIPDATA:
			if (!mCanLockClipData) {
				result = false;
			}
			CWLOG_WRN(TAG, "warning: clipboard locking is not implemented");
			break;

		case CB_FILECONTENTS_REQUEST:
		case CB_FILECONTENTS_RESPONSE:
			if (!mStreamFileClipEnabled) {
				result = false;
			}
			CWLOG_WRN(TAG, "warning: file transfer is not implemented");
			break;

		default:
			CWLOG_ERR(TAG, "error: invalid clipboard pdu type");
			result = false;
			break;
	}

	return result;
}

void RDPClipChannelServer::sessionChange(Status status, quint32 sessionId) {
	//CWLOG_VRB(TAG, "RDPClipChannelServer %s", __FUNCTION__);
	RDPChannelServer::sessionChange(status, sessionId);
}

bool RDPClipChannelServer::start() {
	CWLOG_INF(TAG, "starting clipboard channel server");

	if (!isInitOk() || isStarted() || !RDPChannelServer::start()) {
		return false;
	}

	/* init status values*/
	mInitSequenceCompleted = false;
	mClientCapsReceived = false;
	mClientTemporaryDirectoryReceived = false;
	mRequestedFormat = 0;
	mPeerFormats.clear();
	mHostFormats.clear();
	mPeerCache.clear();
	mClientTemporaryDirectory.clear();
	mPeerFormatListResponseOk = false;
	mNumChangedEventsToIgnore = 0;

	/* init settings */
	mUseLongFormatNames = true;
	mStreamFileClipEnabled = false;
	mFileClipNoFilePaths = false;
	mCanLockClipData = false;

	if (! sendCapabilities() || !sendMonitorReady()) {
		return false;
	}

	return true;
}

bool RDPClipChannelServer::stop() {
	if (!isStarted()) {
		return false;
	}
	CWLOG_INF(TAG, "stopping clipboard channel server");
	return RDPChannelServer::stop();
}

bool RDPClipChannelServer::sendCapabilities() {
	CWLOG_DBG(TAG, "sending capabilities");

	/**
	 * MS-RDPECLIP 2.2.2.1 Clipboard Capabilities PDU (CLIPRDR_CAPS)
	 * http://msdn.microsoft.com/en-us/library/cc241099.aspx
	 * MS-RDPECLIP 2.2.2.1.1 Capability Set (CLIPRDR_CAPS_SET)
	 * http://msdn.microsoft.com/en-us/library/cc241100.aspx
	 * MS-RDPECLIP 2.2.2.1.1 2.2.2.1.1.1 General Capability Set (CLIPRDR_GENERAL_CAPABILITY)
	 * http://msdn.microsoft.com/en-us/library/cc241101.aspx
	 */

	RdpStreamBuffer s;
	quint32 generalFlags = 0;
	qint64 bytesWritten;

	if (mUseLongFormatNames) {
		generalFlags |= CB_USE_LONG_FORMAT_NAMES;
	}
	if (mStreamFileClipEnabled) {
		generalFlags |= CB_STREAM_FILECLIP_ENABLED;
	}
	if (mFileClipNoFilePaths) {
		generalFlags |= CB_FILECLIP_NO_FILE_PATHS;
	}
	if (mCanLockClipData) {
		generalFlags |= CB_CAN_LOCK_CLIPDATA;
	}

	s << quint16(CB_CLIP_CAPS); /* msgType (2 bytes) */
	s << quint16(0); /* msgFlags (2 bytes) */
	s << quint32(16); /* dataLen (4 bytes) */
	s << quint16(1); /* cCapabilitiesSets (2 bytes) */
	s << quint16(0); /* pad1 (2 bytes) */
	s << quint16(CB_CAPSTYPE_GENERAL); /* capabilitySetType (2 bytes) */
	s << quint16(CB_CAPSTYPE_GENERAL_LEN); /* lengthCapability (2 bytes) */
	s << quint32(CB_CAPS_VERSION_2); /* version (4 bytes) */
	s << quint32(generalFlags); /* generalFlags (4 bytes) */
	s.sealLength();

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}
	return true;
}

bool RDPClipChannelServer::sendMonitorReady() {
	CWLOG_DBG(TAG, "sending monitor ready");

	/**
	 * MS-RDPECLIP 2.2.2.2 Server Monitor Ready PDU (CLIPRDR_MONITOR_READY)
	 * http://msdn.microsoft.com/en-us/library/cc241102.aspx
	 */

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(CB_MONITOR_READY); /* msgType (2 bytes) */
	s << quint16(0); /* msgFlags (2 bytes) */
	s << quint32(0); /* dataLen (4 bytes) */
	s.sealLength();

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}
	return true;
}

bool RDPClipChannelServer::sendFormatList() {
	CWLOG_DBG(TAG, "sending format list");

	/**
	 * MS-RDPECLIP 2.2.3.1 Format List PDU (CLIPRDR_FORMAT_LIST)
	 * http://msdn.microsoft.com/en-us/library/cc241105.aspx
	 * MS-RDPECLIP 2.2.3.1.1 Short Format Names (CLIPRDR_SHORT_FORMAT_NAMES)
	 * http://msdn.microsoft.com/en-us/library/cc241106.aspx
	 * MS-RDPECLIP 2.2.3.1.2 Long Format Names (CLIPRDR_LONG_FORMAT_NAMES)
	 * http://msdn.microsoft.com/en-us/library/cc241108.aspx
	 */

	RdpStreamBuffer s;
	quint32 formatId;
	QString formatName;
	qint64 bytesWritten;


	ClipboardFormatsIterator i(mHostFormats);

	s.seek(CLIPRDR_HEADER_LENGTH); /* clipboard header gets written lastly */

	while (i.hasNext()) {
		i.next();
		formatId = i.key();
		formatName = i.value();
		//CWLOG_DBG(TAG, "formatId: %u (%s)", i.key(), QCSTR(i.value()));
		s << formatId;	/* formatId (4 bytes) */

		if (mUseLongFormatNames) {
			if (!formatName.isEmpty()) {
				/* variable length unicode format name */
				s.write((const char *)formatName.unicode(), formatName.length() * 2);
			}
			s << quint16(0); /* terminating unicode null character (2 bytes) */
		}
		else {
			/**
			 * See comment in receiveShortFormatList regarding [MS-RDPECLIP] 2.2.3.1.1.1
			 * truncateded short format strings are truncated without terminating null
			 */
			char shortName[32];
			memset(shortName, 0, sizeof(shortName));
			if (!formatName.isEmpty()) {
				size_t cplen = qMin((size_t)formatName.length() * 2, sizeof(shortName));
				memcpy(shortName, formatName.unicode(), cplen);
			}
			s.write(shortName, sizeof(shortName));
		}
	}
	s.sealLength();

	/* write clipboard header */
	s.setPosition(0);

	s << quint16(CB_FORMAT_LIST); /* msgType (2 bytes) */
	s << quint16(0); /* msgFlags (2 bytes) */
	s << quint32(s.length() - CLIPRDR_HEADER_LENGTH); /* dataLen (4 bytes) */

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}
	return true;
}

bool RDPClipChannelServer::sendFormatListResponse(bool responseOk) {
	CWLOG_DBG(TAG, "sending format list response: responseOk is: %d", responseOk);

	/**
	 * MS-RDPECLIP 2.2.3.2 Format List Response PDU (FORMAT_LIST_RESPONSE)
	 * http://msdn.microsoft.com/en-us/library/cc241120.aspx
	 *
	 * Quote from official specs:
	 * The msgType field of the Clipboard PDU Header MUST be set to
	 * CB_FORMAT_LIST_RESPONSE (0x0003).
	 * The CB_RESPONSE_OK (0x0001) or CB_RESPONSE_FAIL (0x0002) flag MUST be set
	 * in the msgFlags field of the Clipboard PDU Header.
	 */

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(CB_FORMAT_LIST_RESPONSE); /* msgType (2 bytes) */
	s << quint16(responseOk ? CB_RESPONSE_OK : CB_RESPONSE_FAIL); /* msgFlags (2 bytes) */
	s << quint32(0); /* dataLen (4 bytes) */
	s.sealLength();

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}

	mInitSequenceCompleted = true;
	return true;
}

bool RDPClipChannelServer::sendFormatDataRequest(quint32 formatId) {
	CWLOG_DBG(TAG, "sending format data request for format id 0x%08X", formatId);

	mRequestedFormat = 0;

	/**
	 * MS-RDPECLIP 2.2.5.1 Format Data Request PDU (CLIPRDR_FORMAT_DATA_REQUEST)
	 * http://msdn.microsoft.com/en-us/library/cc241122.aspx
	 */

	if (!mPeerFormats.contains(formatId)) {
		CWLOG_WRN(TAG, "warning: data request for invalid formatId 0x%08X", formatId);
		return false;
	}

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(CB_FORMAT_DATA_REQUEST); /* msgType (2 bytes) */
	s << quint16(0); /* msgFlags (2 bytes) */
	s << quint32(4); /* dataLen (4 bytes) */

	s << quint32(formatId); /* formatId (4 bytes) */
	s.sealLength();

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}

	mRequestedFormat = formatId;
	return true;
}

bool RDPClipChannelServer::sendFormatDataResponse(bool responseOk, const QByteArray &data) {
	CWLOG_DBG(TAG, "sending format data response");

	/**
	 * MS-RDPECLIP 2.2.5.2 Format Data Response PDU (CLIPRDR_FORMAT_DATA_RESPONSE)
	 * http://msdn.microsoft.com/en-us/library/cc241123.aspx
	 */

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(CB_FORMAT_DATA_RESPONSE); /* msgType (2 bytes) */
	s << quint16(responseOk ? CB_RESPONSE_OK : CB_RESPONSE_FAIL); /* msgFlags (2 bytes) */
	s << quint32(data.size()); /* dataLen (4 bytes) */
	if (data.size()) {
		s.write(data.constData(), data.size());
	}
	s.sealLength();

	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		return false;
	}
	return true;
}

bool RDPClipChannelServer::receiveCapabilities(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	Q_UNUSED(len);
	CWLOG_DBG(TAG, "receiving capabilities");

	/**
	 * MS-RDPECLIP 2.2.2.1 Clipboard Capabilities PDU (CLIPRDR_CAPS)
	 * http://msdn.microsoft.com/en-us/library/cc241099.aspx
	 * MS-RDPECLIP 2.2.2.1.1 Capability Set (CLIPRDR_CAPS_SET)
	 * http://msdn.microsoft.com/en-us/library/cc241100.aspx
	 * MS-RDPECLIP 2.2.2.1.1.1 General Capability Set (CLIPRDR_GENERAL_CAPABILITY)
	 * http://msdn.microsoft.com/en-us/library/cc241101.aspx
	 */

	if (mClientCapsReceived) {
		return false;
	}
	mClientCapsReceived = true;

	if (flags != 0x0000) {
		CWLOG_ERR(TAG, "error: invalid flags in capabilities pdu: 0x%02X", flags);
		return false;
	}

	if (s.remainingLength() < 4) {
		return false;
	}

	bool generalCapsReceived = false;
	quint16 cCapabilitiesSets;
	quint16 pad1;
	quint16 capabilitySetType;
	quint16 lengthCapability;
	quint32 generalFlags;
	int i;

	s >> cCapabilitiesSets; /* cCapabilitiesSets (2 bytes) */
	s >> pad1; /* pad1 (2 bytes) */

	for (i = 0; i < cCapabilitiesSets; i++) {
		if (s.remainingLength() < 4) {
			return false;
		}

		s >> capabilitySetType; /* capabilitySetType (2 bytes) */
		s >> lengthCapability; /* lengthCapability (2 bytes) */

		if ((lengthCapability < 4) || (s.remainingLength() < (quint32)(lengthCapability - 4))) {
			return false;
		}

		switch (capabilitySetType) {
			case CB_CAPSTYPE_GENERAL:
				if (lengthCapability != CB_CAPSTYPE_GENERAL_LEN) {
					return false;
				}

				s.seek(4); /* version (4 bytes), unused */
				s >> generalFlags; /* generalFlags (4 bytes) */

				generalCapsReceived = true;
				break;

			default:
				CWLOG_WRN(TAG, "unknown capability set type received: 0x%04X", capabilitySetType);
				s.seek(lengthCapability - 4);
		}
	}

	/**
	 * Quote from official specs:
	 * If the General Capability Set is not present in the Clipboard Capabilities
	 * PDU, then the default set of general capabilities MUST be assumed.
	 * By definition the default set does not specify any flags in the
	 * generalFlags field, that is the generalFlags field is set to 0x00000000.
	 */

	if (!generalCapsReceived) {
		generalFlags = 0x00000000;
	}

	/* only enable those caps we've previously announced */
	mUseLongFormatNames &= (generalFlags & CB_USE_LONG_FORMAT_NAMES) ? true : false;
	mStreamFileClipEnabled &= (generalFlags & CB_STREAM_FILECLIP_ENABLED) ? true : false;
	mFileClipNoFilePaths &= (generalFlags & CB_FILECLIP_NO_FILE_PATHS) ? true : false;
	mCanLockClipData &= (generalFlags & CB_CAN_LOCK_CLIPDATA) ? true : false;

#if 0
	if (mUseLongFormatNames) {
		CWLOG_DBG(TAG, "enabled CB_USE_LONG_FORMAT_NAMES");
	}
	if (mStreamFileClipEnabled) {
		CWLOG_DBG(TAG, "enabled CB_STREAM_FILECLIP_ENABLED");
	}
	if (mFileClipNoFilePaths) {
		CWLOG_DBG(TAG, "enabled CB_FILECLIP_NO_FILE_PATHS");
	}
	if (mCanLockClipData) {
		CWLOG_DBG(TAG, "enabled CB_CAN_LOCK_CLIPDATA");
	}
#endif

	return true;
}

bool RDPClipChannelServer::receiveTemporaryDirectory(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	Q_UNUSED(len);
	CWLOG_DBG(TAG, "receiving temporary directory");

	/**
	 * MS-RDPECLIP 2.2.2.3 Client Temporary Directory PDU (CLIPRDR_TEMP_DIRECTORY)
	 * http://msdn.microsoft.com/en-us/library/cc241103.aspx
	 *
	 * Quote from official specs:
	 * The data must be a 520-byte block that contains a null-terminated
	 * UNICODE string that represents the directory on the client that MUST be
	 * used to store temporary clipboard related information.
	 * The supplied path MUST be absolute and relative to the local client
	 * system, for example, "c:\temp\clipdata". Any space not used in this field
	 * SHOULD be filled with null characters.
	 */

	if (mClientTemporaryDirectoryReceived) {
		CWLOG_ERR(TAG, "error: temporary directory pdu was already received");
		return false;
	}
	mClientTemporaryDirectoryReceived = true;

	if (flags != 0x0000) {
		CWLOG_ERR(TAG, "error: invalid flags (0x%04X) in temporary directory pdu", flags);
		return false;
	}

	if (s.remainingLength() < 520) {
		CWLOG_ERR(TAG, "error: temporary directory pdu protocol error");
		return false;
	}

	const quint16 *ustr = (const quint16 *)(s.data() + s.position());

	mClientTemporaryDirectory = QString((const QChar *)ustr);

	CWLOG_DBG(TAG, "ClientTemporaryDirectory: '%s'", QCSTR(mClientTemporaryDirectory));

	return true;
}

bool RDPClipChannelServer::receiveLongFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving long format list");

	/**
	 * MS-RDPECLIP 2.2.3.1 Format List PDU (CLIPRDR_FORMAT_LIST)
	 * http://msdn.microsoft.com/en-us/library/cc241105.aspx
	 * MS-RDPECLIP 2.2.3.1.2 Long Format Names (CLIPRDR_LONG_FORMAT_NAMES)
	 * http://msdn.microsoft.com/en-us/library/cc241108.aspx
	 *
	 * Quote from official specs:
	 * The data holds a list of Format ID and Format name pairs.
	 * formatId (4 bytes): An unsigned, 32-bit integer
	 * wszFormatName (variable): A variable length null-terminated Unicode
	 * string name that contains the Clipboard Format name. Not all Clipboard
	 * Formats have a name; in such cases, the formatName field MUST consist
	 * of a single Unicode null character.
	 */

	if (flags != 0x0000) {
		CWLOG_ERR(TAG, "error: invalid flags (0x%04X) in format list pdu (long names)", flags);
		return false;
	}
	if (len == 0) {	/* clipboard was cleared */
		//CWLOG_VRB(TAG, "clipboard was cleared");
		return true;
	}
	if (s.remainingLength() != len || len % 2 != 0) {
		CWLOG_ERR(TAG, "error: stream length mismatch in format list pdu (long names)");
		return false;
	}

	const quint16 *ustr = NULL;
	const quint16 *uend = NULL;
	const quint16 *uptr = NULL;
	quint32 formatId;
	size_t ulen;

	uend = (const quint16 *)(s.data() + s.length());

	while (s.remainingLength() >= 6) {
		s >> formatId;  /* formatId (4 bytes) */
		ustr = (const quint16 *)(s.data() + s.position());
		for (ulen = 0, uptr = ustr; *uptr != 0 && uptr < uend; uptr++) {
			ulen++;
		}
		if (uptr >= uend) {
			CWLOG_ERR(TAG, "error: long format list protocol error 1");
			mPeerFormats.clear();
			return false;
		}
		mPeerFormats[formatId] = QString((QChar*)ustr);
		s.seek((ulen + 1) * 2);
	}

	if (s.remainingLength() != 0) {
		CWLOG_ERR(TAG, "error: long format list protocol error 2");
		mPeerFormats.clear();
		return false;
	}

	return true;
}

bool RDPClipChannelServer::receiveShortFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving short format list");

	/**
	 * MS-RDPECLIP 2.2.3.1 Format List PDU (CLIPRDR_FORMAT_LIST)
	 * http://msdn.microsoft.com/en-us/library/cc241105.aspx
	 * MS-RDPECLIP 2.2.3.1.1 Short Format Names (CLIPRDR_SHORT_FORMAT_NAMES)
	 * http://msdn.microsoft.com/en-us/library/cc241106.aspx
	 *
	 * Quote from official specs:
	 * The msgFlags field of the Clipboard PDU Header MUST be set to 0x0000 or
	 * CB_ASCII_NAMES (0x0004) depending on the type of data present in
	 * the formatListData field.
	 *
	 * The data holds a list of Format ID and Format name pairs.
	 * formatId (4 bytes): An unsigned, 32-bit integer
	 * formatName (32 bytes): A 32-byte block containing the null-terminated
	 * name assigned to the Clipboard Format (32 ASCII 8 characters or 16
	 * Unicode characters). If the name does not fit, it MUST be truncated.
	 * Not all Clipboard Formats have a name, and in that case the formatName
	 * field MUST contain only zeros.
	 */

	bool useAsciiNames;

	if (flags == 0x0000) {
		useAsciiNames = false;
	}
	else if (flags == 0x0004) {
		useAsciiNames = true;
	}
	else {
		CWLOG_ERR(TAG, "error: invalid flags (0x%04X) in format list pdu (short names)", flags);
		return false;
	}

	if (len == 0) {	/* clipboard was cleared */
		//CWLOG_DBG(TAG, "clipboard was cleared");
		return true;
	}
	if (s.remainingLength() != len || len % 2 != 0) {
		CWLOG_ERR(TAG, "error: stream length mismatch in format list pdu (short names)");
		return false;
	}

	CWLOG_DBG(TAG, "useAsciiNames: %d", useAsciiNames);

	/**
	 * NOTE: Contrary to [MS-RDPECLIP] 2.2.3.1.1.1 the strings are not
	 * necessarily null-terminated!! Just one prominent example in unicode
	 * sent by mstsc is "R.i.c.h. .T.e.x.t. .F.o.r.m.a.t."
	 * That's 16 unicode characters bytes without terminating null.
	 */

	quint32 formatId;

	/**
	 * workaround Microsoft's protocol violation by creating a buffer that
	 * will hold a guaranteed null-terminated unicode or ascii string copy
	 */
	char tmpbuf[34];
	memset(tmpbuf + 32, 0, 2);

	while (s.remainingLength() >= 36) {
		s >> formatId;  /* formatId (4 bytes) */
		memcpy(tmpbuf, s.data() + s.position(), 32);
		if (useAsciiNames) {
			mPeerFormats[formatId] = QString((const char *)tmpbuf);
		} else {
			mPeerFormats[formatId] = QString((const QChar *)tmpbuf);
		}
		s.seek(32);
	}

	if (s.remainingLength() != 0) {
		CWLOG_ERR(TAG, "error: long format list protocol error");
		mPeerFormats.clear();
		return false;
	}

	return true;
}

bool RDPClipChannelServer::receiveFormatList(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	//CWLOG_DBG(TAG, "receiving format list");

	/**
	 * MS-RDPECLIP 2.2.3.1 Format List PDU (CLIPRDR_FORMAT_LIST)
	 * http://msdn.microsoft.com/en-us/library/cc241105.aspx
	 */

	bool result;

	mPeerFormats.clear();
	mPeerCache.clear();
	mRequestedFormat = 0;
	mPeerRequestQueue.clear();

	if (mUseLongFormatNames) {
		result = receiveLongFormatList(flags, len, s);
	} else {
		result = receiveShortFormatList(flags, len, s);
	}

	if (!result) {
		sendFormatListResponse(false);
		return false;
	}

	result = sendFormatListResponse(true);

	if (!result) {
		return false;
	}

	if (mPeerFormats.empty()) {
		/* Peer has nothing to offer, probably the clipboard was cleared */
		mClipboard->clear(mClipboardMode);
		return true;
	}

	quint32 textFormatId = 0;
	quint32 unicodeTextFormatId = 0;
	quint32 htmlFormatId = 0;

	ClipboardFormatsIterator i(mPeerFormats);
	while (i.hasNext()) {
		i.next();
		if (i.key() == CF_UNICODETEXT) {
			unicodeTextFormatId = i.key();
		} else if (i.key() == CF_TEXT) {
			textFormatId = i.key();
		} else if (i.value() == "HTML Format") {
			htmlFormatId = i.key();
		}
	}

	if (!mUseDelayedRendering) {
		/**
		 * if delayed rendering is not used we have to retrieve all known
		 * formats immediately. we enqueue the format ids and send out format
		 * data request for all of them. the first request is sent right here
		 * and the requests for the remaining format ids in the queue will be
		 * triggered in receiveFormatDataResponse()
		 */

		if (unicodeTextFormatId) {
			mPeerRequestQueue.enqueue(unicodeTextFormatId);
		} else if (textFormatId) {
			mPeerRequestQueue.enqueue(textFormatId);
		}

		if (htmlFormatId) {
			mPeerRequestQueue.enqueue(htmlFormatId);
		}

		if (!mPeerRequestQueue.isEmpty()) {
			/* immediately start requesting the first format */
			result = sendFormatDataRequest(mPeerRequestQueue.dequeue());
		}

		return result;
	}

	/**
	 * delayed rendering is used:
	 * Note: QT's clipboard does not support this.
	 * we solve this shortcoming by setting empty data for the supported
	 * formats. the user of this class is responsible for hooking the platform
	 * specific native event loop in order to intercept clipboard data requests
	 * and to call the sendTextFormatRequest() and/or sendHtmlFormatRequest()
	 * functions of this class.
	 */


	/*
	 * Note: the allocated QMimeData set via QClipboard's setMimeData() will
	 * automatically be freed by QClipboard
	 */

	QMimeData *mime = new QMimeData;

	if (unicodeTextFormatId || textFormatId) {
		mime->setText("");
	}
	if (htmlFormatId) {
		mime->setHtml("");
	}
	setClipboardMimeData(mime);

	return true;
}

bool RDPClipChannelServer::receiveFormatListResponse(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	Q_UNUSED(s);
	Q_UNUSED(len);
	CWLOG_DBG(TAG, "receiving format list response");

	/**
	 * MS-RDPECLIP 3.1.5.2.4 Processing a Format List Response PDU
	 * If the response code indicates that processing of the Format List PDU was
	 * unsuccessful, then the recipient MUST respond to any subsequent Format
	 * Data Request PDUs or File Contents Request PDUs by sending a Format Data
	 * Response or File Contents Response indicating failure
	 */

	mPeerFormatListResponseOk = false;

	if (flags != CB_RESPONSE_OK && flags != CB_RESPONSE_FAIL) {
		CWLOG_ERR(TAG, "error: invalid flags (0x%04X) in format list response pdu", flags);
		return false;
	}
	if (len != 0) {
		CWLOG_DBG(TAG, "error: invalid length in format list response pdu header");
		return false;
	}

	if (flags == CB_RESPONSE_OK) {
		mPeerFormatListResponseOk = true;
	} else {
		mPeerFormatListResponseOk = false;
	}

	return true;
}

bool RDPClipChannelServer::receiveFormatDataRequest(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving format data request");

	/**
	 * MS-RDPECLIP 2.2.5.1 Format Data Request PDU (CLIPRDR_FORMAT_DATA_REQUEST)
	 * http://msdn.microsoft.com/en-us/library/cc241122.aspx
	 */

	if (flags != 0x0000) {
		CWLOG_DBG(TAG, "error: invalid flags (0x%04X) in format data request pdu", flags);
		return false;
	}
	if (len != 4) {
		CWLOG_DBG(TAG, "error: invalid length in format data request pdu header");
		return false;
	}

	QByteArray data;

	if (!mPeerFormatListResponseOk) {
		/* See [MSRDPECLIP] 3.1.5.2.4: ... MUST respond ... indicating failure */
		return sendFormatDataResponse(false, data);
	}

	quint16 formatId;

	s >> formatId; /* requestedFormatId (2 bytes) */

	if (!mHostFormats.contains(formatId)) {
		CWLOG_WRN(TAG, "warning: request for non-existent format id 0x%04X", formatId);
		return true;
	}

#if 0
	QString dbgFormatName(mHostFormats[formatId]);
	if (dbgFormatName.isEmpty()) {
		if (formatId == CF_TEXT) {
			dbgFormatName = "empty (CF_TEXT id)";
		} else if (formatId == CF_UNICODETEXT) {
			dbgFormatName = "empty (CF_UNICODETEXT id)";
		}
	}
	CWLOG_DBG(TAG, "requested format id 0x%04X, name: %s", formatId, QCSTR(dbgFormatName));
#else
	CWLOG_DBG(TAG, "requested format id 0x%04X", formatId);
#endif

	bool result = true;

	const QMimeData *mime = mClipboard->mimeData(mClipboardMode);

	if (formatId == CF_TEXT && mime->hasText()) {
		data = QByteArray(mime->text().replace("\n", "\r\n").toLatin1());
	} else if (formatId == CF_UNICODETEXT && mime->hasText()) {
		const QString s = mime->text().replace("\n", "\r\n");
		data = QByteArray((const char *)s.unicode(), s.size() * 2 + 2);
	}
	else if (mHostFormats[formatId] == "HTML Format" && mime->hasHtml()) {
		QString header("Version:1.0\r\nStartHTML:xxxxxxxxxx\r\nEndHTML:xxxxxxxxxx\r\nStartFragment:xxxxxxxxxx\r\nEndFragment:xxxxxxxxxx\r\n");
		const QByteArray content(mime->html().toUtf8());
		header.replace("StartHTML:xxxxxxxxxx", QString("StartHTML:%1").arg(header.length(), 10, 10, QLatin1Char('0')));
		header.replace("EndHTML:xxxxxxxxxx", QString("EndHTML:%1").arg(header.length() + content.size(), 10, 10, QLatin1Char('0')));
		header.replace("StartFragment:xxxxxxxxxx", QString("StartFragment:%1").arg(header.length(), 10, 10, QLatin1Char('0')));
		header.replace("EndFragment:xxxxxxxxxx", QString("EndFragment:%1").arg(header.length() + content.size(), 10, 10, QLatin1Char('0')));
		data = QByteArray(header.toLatin1()) + content;
	} else {
		result = false;
	}

	return sendFormatDataResponse(result, data);
}

bool RDPClipChannelServer::receiveFormatDataResponse(quint16 flags, quint32 len, RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving format data response");

	/**
	 * MS-RDPECLIP 2.2.5.2 Format Data Response PDU (CLIPRDR_FORMAT_DATA_RESPONSE)
	 * http://msdn.microsoft.com/en-us/library/cc241123.aspx
	 */

	quint32 requestedFormat = mRequestedFormat;
	mRequestedFormat = 0;

	if (flags != CB_RESPONSE_OK && flags != CB_RESPONSE_FAIL) {
		CWLOG_ERR(TAG, "error: invalid flags (0x%04X) in format data response pdu", flags);
		return false;
	}
	if (s.remainingLength() != len) {
		CWLOG_ERR(TAG, "error: stream length mismatch in format data response pdu (short names)");
		return false;
	}

	if (flags == CB_RESPONSE_FAIL) {
		CWLOG_WRN(TAG, "warning: peer sent format data response failure");
		return true;
	}

	if (requestedFormat == 0 || !mPeerFormats.contains(requestedFormat)) {
		CWLOG_WRN(TAG, "warning: invalid or delayed format data response");
		return true;
	}

	if (len == 0) {
		CWLOG_WRN(TAG, "warning: format data response with empty data");
		return true;
	}

	const char *data = s.data() + s.position();

	if (requestedFormat == CF_UNICODETEXT) {
		if (len >= 4 && len % 2 == 0) {
			QString str((const QChar *)data, (len - 2) / 2);
			//CWLOG_DBG(TAG, "CF_UNICODETEXT: [%s]", QCSTR(str));
			mPeerCache.setText(str.replace("\r\n", "\n"));
		}
	} else if (requestedFormat == CF_TEXT) {
		if (data[len - 1] == 0) {
			QString str((const char *)data);
			//CWLOG_DBG(TAG, "CF_TEXT: [%s]", QCSTR(str));
			mPeerCache.setText(str.replace("\r\n", "\n"));
		}
	} else if (mPeerFormats[requestedFormat] == "HTML Format") {
		QByteArray html(data, len);
		int start = html.indexOf("StartHTML:");
		int end = html.indexOf("EndHTML:");

		if (start != -1) {
			int startOffset = start + 10;
			int i = startOffset;
			while (html.at(i) != '\r' && html.at(i) != '\n')
				++i;
			QByteArray bytecount = html.mid(startOffset, i - startOffset);
			start = bytecount.toInt();
		}
		if (end != -1) {
			int endOffset = end + 8;
			int i = endOffset ;
			while (html.at(i) != '\r' && html.at(i) != '\n')
				++i;
			QByteArray bytecount = html.mid(endOffset , i - endOffset);
			end = bytecount.toInt();
		}
		if (end > start && start > 0) {
			html = html.mid(start, end - start);
			html.replace('\r', "");
			html.replace("<!--StartFragment-->", "");
			html.replace("<!--EndFragment-->", "");
			//CWLOG_DBG(TAG, "HTML: [%s]", html.constData());
			mPeerCache.setHtml(QString::fromUtf8(html));
		}
	}

	QMimeData *mime = NULL;

	if (!mUseDelayedRendering) {
		/* immediately request the next format */
		while (!mPeerRequestQueue.isEmpty()) {
			requestedFormat = mPeerRequestQueue.dequeue();
			if (mPeerFormats.contains(requestedFormat)) {
				sendFormatDataRequest(requestedFormat);
				break;
			}
			CWLOG_WRN(TAG, "warning: request for invalid data format id prevented");
		}

		if (!isWaitingForFormatDataResponse()) {
			/**
			 * No additional request was sent. that means we have received all
			 * format data responses and we may update the clipboard now,
			 */
			if (mPeerCache.hasHtml() || mPeerCache.hasText()) {
				mime = new QMimeData;
				if (mPeerCache.hasHtml()) {
					mime->setHtml(mPeerCache.html());
				}
				if (mPeerCache.hasText()) {
					mime->setText(mPeerCache.text());
				}
				setClipboardMimeData(mime);
			}
		}

		return true;
	}

	/**
	 * if delayed rendering is used we have to update qclipboard's const
	 * mimedata now (yes, that's a bit hackish)
	 **/

	mime = (QMimeData *)mClipboard->mimeData(mClipboardMode);

	if (mPeerCache.hasHtml()) {
		mime->setHtml(mPeerCache.html());
	}
	if (mPeerCache.hasText()) {
		mime->setText(mPeerCache.text());
	}

	return true;
}

