/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * File System Virtual Channel Qt Class
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
#include <QMimeData>
#include <QStringList>
#include <QHash>
#include <QMutexLocker>
#include <QtEndian>
#include "rdpdrchannelserver.h"

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <mntent.h>

/**
 * Official protocol specification:
 * MS-RDPEFS Remote Desktop Protocol: File System Virtual Channel Extension
 * http://msdn.microsoft.com/en-us/library/cc241305.aspx
 */

RDPDrChannelServer::RDPDrChannelServer(QCoreApplication *app,
	bool useSessionNotification, QObject *parent)
	: RDPChannelServer(WTS_CURRENT_SERVER, WTS_CURRENT_SESSION, "RDPDR", true, parent)
	, mUseSessionNotification(useSessionNotification)
{
	if (!app) {
		CWLOG_FTL(TAG, "fatal: cannot work with null application");
		abort();
	}

	mResponseTimeout = 20000;

	mMountPointRule = "{HOME}/rdpfiles/{CLIENTNAME}/{SESSIONID}/{DEVICENAME}/";

	if (mUseSessionNotification) {
		registerSessionNotification(NotifyForThisSession);
	}

	connect(unixSignalHandler, SIGNAL(activated(int)), this, SLOT(handleUnixSignal(int)));
	unixSignalHandler->watch(SIGHUP);
	unixSignalHandler->watch(SIGINT);
	unixSignalHandler->watch(SIGTERM);

	mMainLock = new QMutex(QMutex::Recursive);
}

RDPDrChannelServer::~RDPDrChannelServer() {
	unixSignalHandler->destroy();
	stop();
	delete mMainLock;
}

void RDPDrChannelServer::handleUnixSignal(int signum) {
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

bool RDPDrChannelServer::processPDU(RdpStreamBuffer &stream) {
	bool result = true;
	quint16 component;
	quint16 packetId;

	//CWLOG_VRB("processPDU streampos: %lu data: [%s]", stream.position(), stream.toHex().constData());

	stream >> component; /* HeaderComponent (2 bytes) */
	stream >> packetId; /* HeaderPacketId (2 bytes) */

	//CWLOG_VRB("processPDU component: %u packetId: %u", component, packetId);

	if (component == RDPDR_CTYP_CORE) {
		switch(packetId) {
			case PAKID_CORE_CLIENTID_CONFIRM:
				if (mProtocolState != ProtocolStateWaitingAnnounceReply) {
					CWLOG_ERR(TAG, "protocol state error for core packet %d", packetId);
					return false;
				}
				if (!receiveAnnounceReply(stream)) {
					return false;
				}
				mProtocolState = ProtocolStateWaitingNameRequest;
				break;

			case PAKID_CORE_CLIENT_NAME:
				if (mProtocolState != ProtocolStateWaitingNameRequest) {
					CWLOG_ERR(TAG, "protocol state error for core packet %d", packetId);
					return false;
				}
				if (!receiveNameRequest(stream)) {
					return false;
				}
				if (!sendCoreCapabilityRequest()) {
					return false;
				}
				if (!sendClientIdConfirm()) {
					return false;
				}
				mProtocolState = ProtocolStateWaitingCapabilityResponse;
				break;

			case PAKID_CORE_CLIENT_CAPABILITY:
				if (mProtocolState != ProtocolStateWaitingCapabilityResponse) {
					CWLOG_ERR(TAG, "protocol state error for core packet %d", packetId);
					return false;
				}
				if (!receiveCoreCapabilityResponse(stream)) {
					return false;
				}
				if (mSendUserLoggedOnPdu && !sendUserLoggedOn()) {
					return false;
				}
				mProtocolState = ProtocolStateRunning;
				break;

			case PAKID_CORE_DEVICELIST_ANNOUNCE:
				if (mProtocolState != ProtocolStateRunning) {
					CWLOG_ERR(TAG, "protocol state error for core packet %d", packetId);
					return false;
				}
				if (!receiveDeviceListAnnounceRequest(stream)) {
					return false;
				}
				break;

			case PAKID_CORE_DEVICE_IOCOMPLETION:
				if (!receiveDeviceIoCompletion(stream)) {
					return false;
				}
				break;

			case PAKID_CORE_DEVICELIST_REMOVE:
				if (mProtocolState != ProtocolStateRunning) {
					CWLOG_ERR(TAG, "protocol state error for core packet %d", packetId);
					return false;
				}
				if (!receiveDeviceListRemoveRequest(stream)) {
					return false;
				}
				break;
		}
	} else if (component == RDPDR_CTYP_PRN) {
		/* Not implemented */
		switch(packetId) {
			case PAKID_PRN_CACHE_DATA:
				break;
			case PAKID_PRN_USING_XPS:
				break;
		}
	} else  {
		//CWLOG_ERR(TAG, "invalid rdpdr header component %d (data: %s)", component, stream.toHex().constData());
		result = false;
	}

	return result;
}

bool RDPDrChannelServer::processReceivedData(RdpStreamBuffer &stream) {
	//CWLOG_VRB("%s: stream.remainingLength(): %lu", __FUNCTION__, stream.remainingLength());

	if (mProtocolState == ProtocolStateInit) {
		CWLOG_ERR(TAG, "protocol state error: received data in init state");
		return false;
	}

	if (!stream.verifyRemainingLength(RDPDR_HEADER_LENGTH) || !processPDU(stream)) {
		CWLOG_ERR(TAG, "failed to handle PDU.");
		if (stream.requiredLengthError()) {
			CWLOG_ERR(TAG, "input stream required length error value: %lu", stream.requiredLengthError());
		}
		return false;
	}

#if 0
	if (stream.remainingLength()) {
		CWLOG_VRB("unprocessed remaining PDU bytes: %lu", stream.remainingLength());
	}
#endif

	return true;
}

void RDPDrChannelServer::sessionChange(Status status, quint32 sessionId) {
	if (status == RDPSessionNotification::WtsSessionLogoff) {
		qApp->exit(0);
	} else {
		RDPChannelServer::sessionChange(status, sessionId);
	}
}

bool RDPDrChannelServer::start() {
	CWLOG_INF(TAG, "starting device redirection channel server");

	if (!isInitOk() || isStarted() || !RDPChannelServer::start()) {
		return false;
	}

	if (mDevices.size()) {
		CWLOG_ERR(TAG, "error: started channel with non-empty devices");
		return false;
	}

	if (mResponses.size()) {
		CWLOG_ERR(TAG, "error: started channel with non-empty responses");
		return false;
	}


	/* init status values */
	mProtocolState = ProtocolStateInit;
	mNextCompletionId = 1;
	reusableCompletionIds.clear();

	/* init settings */
	mSendUserLoggedOnPdu = true;

	mHavePrinterCapability = false;
	mHavePortCapability = false;
	mHaveDriveCapability = true;
	mHaveSmartCardCapability = false;

	mIsBuggyRdesktop = false;

	if (!sendAnnounceRequest()) {
		CWLOG_ERR(TAG, "error: failed to send server announce request");
		return false;
	}

	mProtocolState = ProtocolStateWaitingAnnounceReply;
	return true;
}

bool RDPDrChannelServer::stop() {
	if (!isStarted()) {
		return false;
	}

	CWLOG_INF(TAG, "stopping device redirection channel server");

	RDPChannelServer::stop();

	/* remove all devices */

	for (RdpDrDevicesIterator it = mDevices.begin(); it != mDevices.end(); ++it) {
		removeDevice(it.value());
	}

	QMutexLocker locker(mMainLock);

	for (RdpDrDevicesIterator it = mDevices.begin(); it != mDevices.end(); ++it) {
		CWLOG_DBG(TAG, "deleting device id %u", it.value()->id);
		if (!it.value()->disabled) {
			CWLOG_ERR(TAG, "error device id %u is still enabled", it.value()->id);
		}
		delete it.value();
	}
	mDevices.clear();

	if (mResponses.size()) {
		CWLOG_ERR(TAG, "error: non-empty response map after channel termination");
		mResponses.clear();
	}

	return true;
}

bool RDPDrChannelServer::setMountPointRule(const QString &rule) {
	/* FIXME: do some verification regarding the rule */
	mMountPointRule = rule;
	return true;
}

bool RDPDrChannelServer::setResponseTimeout(quint32 ms) {
	/* FIXME: do some sanity checks */
	mResponseTimeout = ms;
	return true;
}

bool RDPDrChannelServer::sendAnnounceRequest() {
	CWLOG_DBG(TAG, "sending announce request");

	/**
	 * MS-RDPEFS 2.2.2.2 Server Announce Request (DR_CORE_SERVER_ANNOUNCE_REQ)
	 * http://msdn.microsoft.com/en-us/library/cc241343.aspx
	 */

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
	s << quint16(PAKID_CORE_SERVER_ANNOUNCE); /* HeaderPacketId (2 bytes) */

	s << quint16(0x0001); /* VersionMajor (2 bytes) */
	s << quint16(0x000C); /* VersionMinor (2 bytes) */

	/**
	 * http://msdn.microsoft.com/en-us/library/cc241452.aspx
	 * The ClientId field MUST be set to a unique ID that will not collide with
	 * any other connection where this protocol is used.
	 */

	mClientId = qApp->applicationPid();

	s << quint32(mClientId); /* ClientId (4 bytes) */

	s.sealLength();

	if ((bytesWritten = writeData(s)) < 0) {
		return false;
	}

	return true;
}

bool RDPDrChannelServer::sendCoreCapabilityRequest() {
	CWLOG_DBG(TAG, "sending core capability request");

	RdpStreamBuffer s;
	qint64 bytesWritten;
	quint16 numCapabilities = 1;

	if (mHavePrinterCapability) {
		numCapabilities++;
	}
	if (mHavePortCapability) {
		numCapabilities++;
	}
	if (mHaveDriveCapability) {
		numCapabilities++;
	}
	if (mHaveSmartCardCapability) {
		numCapabilities++;
	}

	CWLOG_DBG(TAG, "PrinterCapability:     %d", mHavePrinterCapability);
	CWLOG_DBG(TAG, "PortCapability:        %d", mHavePortCapability);
	CWLOG_DBG(TAG, "DriveCapability:       %d", mHaveDriveCapability);
	CWLOG_DBG(TAG, "SmartCardCapability:   %d", mHaveSmartCardCapability);

	s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
	s << quint16(PAKID_CORE_SERVER_CAPABILITY); /* HeaderPacketId (2 bytes) */

	s << quint16(numCapabilities); /* numCapabilities (2 bytes) */
	s << quint16(0x0000); /* Padding (2 bytes) */

	/* General capability set */
	s << quint16(CAP_GENERAL_TYPE); /* CapabilityType (2 bytes) */
	s << quint16(RDPDR_CAPABILITY_HEADER_LENGTH + 36); /* CapabilityLength (2 bytes) */
	s << quint32(DRIVE_CAPABILITY_VERSION_02); /* Version (4 bytes) */

	quint32 osType = 0x00000002; /* OS_TYPE_WINNT */
	quint32 osVersion = 0x00000000;
	quint16 versionMajor = 0x0001;
	quint16 versionMinor = 0x000C;
	quint32 ioCode1 = 0;
	quint32 ioCode2 = 0;
	quint32 extendedPdu = 0;
	quint32 extraFlags1 = 0;
	quint32 extraFlags2 = 0;
	quint32 specialTypeDeviceCap = 0;

	ioCode1 |= RDPDR_IRP_MJ_CREATE; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_CLEANUP; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_CLOSE; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_READ; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_WRITE; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_FLUSH_BUFFERS; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_SHUTDOWN; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_DEVICE_CONTROL; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_QUERY_VOLUME_INFORMATION; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_SET_VOLUME_INFORMATION; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_QUERY_INFORMATION; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_SET_INFORMATION; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_DIRECTORY_CONTROL; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_LOCK_CONTROL; /* always set */
	ioCode1 |= RDPDR_IRP_MJ_QUERY_SECURITY; /* optional */
	ioCode1 |= RDPDR_IRP_MJ_SET_SECURITY; /* optional */

	extendedPdu |= RDPDR_DEVICE_REMOVE_PDUS; /* optional, allows the client to send Client Drive Device List Remove packets. */
	extendedPdu |= RDPDR_CLIENT_DISPLAY_NAME_PDU; /* Unused, always set */
	extendedPdu |= RDPDR_USER_LOGGEDON_PDU; /* Allow the server to send a Server User Logged On packet */

	/**
	 * Note: According to the spec the extendedPdu/RDPDR_USER_LOGGEDON_PDU and
	 * the extraFlags1/ENABLE_ASYNCIO bits are only used in the Client to Server
	 * Core Capability Response.
	 * However, windows terminal services also sets the RDPDR_USER_LOGGEDON_PDU
	 * bit in the server to client Core Capability Request.
	 * Otherwise the client probably does not know if it has to wait for the
	 * user logged on message in order to announce the non-essential devices.
	 */

	s << quint32(osType); /* osType (4 bytes), ignored on receipt */
	s << quint32(osVersion); /* osVersion (4 bytes), unused and must be set to zero */
	s << quint16(versionMajor); /* protocolMajorVersion (2 bytes) */
	s << quint16(versionMinor); /* protocolMinorVersion (2 bytes) */
	s << quint32(ioCode1); /* ioCode1 (4 bytes) */
	s << quint32(ioCode2); /* ioCode2 (4 bytes), must be set to zero, reserved for future use */
	s << quint32(extendedPdu); /* extendedPdu (4 bytes) */
	s << quint32(extraFlags1); /* extraFlags1 (4 bytes) */
	s << quint32(extraFlags2); /* extraFlags2 (4 bytes), must be set to zero, reserved for future use */
	s << quint32(specialTypeDeviceCap); /* SpecialTypeDeviceCap (4 bytes) */

	/* Printer capability set */
	if (mHavePrinterCapability) {
		s << quint16(CAP_PRINTER_TYPE); /* CapabilityType (2 bytes) */
		s << quint16(RDPDR_CAPABILITY_HEADER_LENGTH); /* CapabilityLength (2 bytes) */
		s << quint32(DRIVE_CAPABILITY_VERSION_01); /* Version (4 bytes) */
	}

	/* Port capability set */
	if (mHavePortCapability) {
		s << quint16(CAP_PORT_TYPE); /* CapabilityType (2 bytes) */
		s << quint16(RDPDR_CAPABILITY_HEADER_LENGTH); /* CapabilityLength (2 bytes) */
		s << quint32(DRIVE_CAPABILITY_VERSION_01); /* Version (4 bytes) */
	}

	/* Drive capability set */
	if (mHaveDriveCapability) {
		s << quint16(CAP_DRIVE_TYPE); /* CapabilityType (2 bytes) */
		s << quint16(RDPDR_CAPABILITY_HEADER_LENGTH); /* CapabilityLength (2 bytes) */
		s << quint32(DRIVE_CAPABILITY_VERSION_02); /* Version (4 bytes) */
	}

	/* SmartCard capability set */
	if (mHaveSmartCardCapability) {
		s << quint16(CAP_SMARTCARD_TYPE); /* CapabilityType (2 bytes) */
		s << quint16(RDPDR_CAPABILITY_HEADER_LENGTH); /* CapabilityLength (2 bytes) */
		s << quint32(DRIVE_CAPABILITY_VERSION_01); /* Version (4 bytes) */
	}

	s.sealLength();

	if ((bytesWritten = writeData(s)) < 0) {
		return false;
	}

	return true;
}

bool RDPDrChannelServer::sendClientIdConfirm() {
	CWLOG_DBG(TAG, "sending client Id confirm");

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
	s << quint16(PAKID_CORE_CLIENTID_CONFIRM); /* HeaderPacketId (2 bytes) */

	s << quint16(0x0001); /* VersionMajor (2 bytes) */
	s << quint16(0x000C); /* VersionMinor (2 bytes) */
	s << quint32(mClientId); /* ClientId (4 bytes) */

	s.sealLength();

	if ((bytesWritten = writeData(s)) < 0) {
		return false;
	}

	return true;
}

bool RDPDrChannelServer::sendUserLoggedOn() {
	CWLOG_DBG(TAG, "sending user logged on");
	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
	s << quint16(PAKID_CORE_USER_LOGGEDON); /* HeaderPacketId (2 bytes) */

	s.sealLength();

	if ((bytesWritten = writeData(s)) < 0) {
		return false;
	}

	return true;
}

bool RDPDrChannelServer::sendDeviceAnnounceResponse(quint32 deviceId, quint32 resultCode) {
	CWLOG_DBG(TAG, "sending device announce response, deviceId: %u resultCode: 0x%08X", deviceId, resultCode);

	RdpStreamBuffer s;
	qint64 bytesWritten;

	s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
	s << quint16(PAKID_CORE_DEVICE_REPLY); /* HeaderPacketId (2 bytes) */

	s << deviceId; /* DeviceId (4 bytes) */
	s << resultCode; /* ResultCode (4 bytes) */

	s.sealLength();

	if ((bytesWritten = writeData(s)) < 0) {
		return false;
	}

	return true;
}

bool RDPDrChannelServer::receiveAnnounceReply(RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving announce reply");

	if (!s.verifyRemainingLength(8)) {
		return false;
	}

	quint16 versionMajor;
	quint16 versionMinor;
	quint32 clientId;

	s >> versionMajor; /* VersionMajor (2 bytes) */
	s >> versionMinor; /* VersionMinor (2 bytes) */
	s >> clientId; /* ClientId (4 bytes) */

	CWLOG_DBG(TAG, "received ClientId: %u with version: %u.%u", clientId, versionMajor, versionMinor);

	if (clientId == mClientId) {
		return true;
	}

	CWLOG_ERR(TAG, "error: invalid client id received: %u instead of %u", clientId, mClientId);

	/**
	 * rdesktop until svn rev r1833 (2014-09-11) always sends the static value
	 * 2647875201 instead of the client id which we've sent in the announce request.
	 * r1833 tries to make it right but has an endianness error when sending the
	 * id. All rdesktop revisions (at least up to r1836 2014-09-11) also have an
	 * endianness error when decoding the Device Create Request's desiredAccess
	 * value.
	 * Here we can reliably detect buggy rdesktop clients and use this to
	 * byte-swap our own desiredAccess value before it gets encoded.
	 */

	if (clientId == 2647875201 || clientId == qbswap(mClientId)) {
		CWLOG_WRN(TAG, "warning: accepting invalid client id from rdesktop");
		mClientId = clientId;
		mIsBuggyRdesktop = true;
		return true;
	}

	return false;
}

bool RDPDrChannelServer::receiveNameRequest(RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving name request");

	if (!s.verifyRemainingLength(12)) {
		return false;
	}

	quint32 unicodeFlag;
	quint32 codePage;
	quint32 computerNameLen;

	s >> unicodeFlag; /* UnicodeFlag (4 bytes) */
	s >> codePage; /* CodePage (4 bytes), MUST be set to zero */
	s >> computerNameLen; /* ComputerNameLen (4 bytes) */

	if (codePage != 0) {
		CWLOG_ERR(TAG, "error: invalid code page value received: %u", codePage);
		return false;
	}

	if (!s.verifyRemainingLength(computerNameLen)) {
		return false;
	}

	/**
	 * Caution: ComputerNameLen is given *bytes*,
	 * not in characters, including the NULL terminator!
	 */

	const char *data = s.pointer();
	s.seek(computerNameLen);

	if (unicodeFlag)
	{
		if (computerNameLen < 4) {
			CWLOG_ERR(TAG, "error: invalid unicode computer name length: %u", computerNameLen);
			return false;
		}
		if (data[computerNameLen-1] != 0 || data[computerNameLen-2] != 0) {
			CWLOG_ERR(TAG, "error: invalid unicode computer name data");
			return false;
		}
		mClientComputerName = QString((const QChar *)data);
	}
	else
	{
		if (computerNameLen < 2) {
			CWLOG_ERR(TAG, "error: invalid ascii computer name length: %u", computerNameLen);
			return false;
		}
		if (data[computerNameLen-1] != 0) {
			CWLOG_ERR(TAG, "error: invalid ascii computer name data");
			return false;
		}
		mClientComputerName = QString((const char *)data);
	}

	if (mClientComputerName.isEmpty()) {
		mClientComputerName = "CLIENTID-" + QString::number(this->mClientId);
	}

	CWLOG_DBG(TAG, "computerName: [%s]", QCSTR(mClientComputerName));
	return true;
}

bool RDPDrChannelServer::receiveCoreCapabilityResponse(RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving core capability response");

	if (!s.verifyRemainingLength(4)) {
		return false;
	}

	quint16 numCapabilities;
	quint16 pad16;

	s >> numCapabilities;  /* numCapabilities (2 bytes) */
	s >> pad16;  /* Padding (2 bytes) */

	CWLOG_DBG(TAG, "numCapabilities: %u", numCapabilities);

	for (int i = 0; i < numCapabilities; i++) {
		quint16 capabilityType;
		quint16 capabilityLength;
		quint32 version;

		if (!s.verifyRemainingLength(RDPDR_CAPABILITY_HEADER_LENGTH)) {
			return false;
		}

		s >> capabilityType;  /* CapabilityType (2 bytes) */
		s >> capabilityLength; /* CapabilityLength (2 bytes) */
		s >> version; /* Version (4 bytes) */

		if (capabilityLength < RDPDR_CAPABILITY_HEADER_LENGTH) {
			CWLOG_ERR(TAG, "error: invalid cap length %u for cap type %u", capabilityLength, capabilityType);
			return false;
		}
		if (!s.verifyRemainingLength(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH)) {
			return false;
		}

		switch (capabilityType) {
			case CAP_GENERAL_TYPE: {
				if (!s.verifyRemainingLength(36)) {
					return false;
				}
				quint32 osType;
				quint32 osVersion;
				quint16 versionMajor;
				quint16 versionMinor;
				quint32 ioCode1;
				quint32 ioCode2;
				quint32 extendedPdu;
				quint32 extraFlags1;
				quint32 extraFlags2;
				quint32 specialTypeDeviceCap;

				s >> osType; /* osType (4 bytes), ignored on receipt */
				s >> osVersion; /* osVersion (4 bytes), unused and must be set to zero */
				s >> versionMajor; /* protocolMajorVersion (2 bytes) */
				s >> versionMinor; /* protocolMinorVersion (2 bytes) */
				s >> ioCode1; /* ioCode1 (4 bytes) */
				s >> ioCode2; /* ioCode2 (4 bytes), must be set to zero, reserved for future use */
				s >> extendedPdu; /* extendedPdu (4 bytes) */
				s >> extraFlags1; /* extraFlags1 (4 bytes) */
				s >> extraFlags2; /* extraFlags2 (4 bytes), must be set to zero, reserved for future use */
				s >> specialTypeDeviceCap; /* SpecialTypeDeviceCap (4 bytes) */

				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH - 36); /* Skip undocumented data or padding */

				mSendUserLoggedOnPdu &= (extendedPdu & RDPDR_USER_LOGGEDON_PDU) ? true : false;

				CWLOG_DBG(TAG, "received CAP_GENERAL_TYPE (osType: %u Version: %u.%u RDPDR_USER_LOGGEDON_PDU bit: %s)",
						 osType, versionMajor, versionMinor,
						 extendedPdu & RDPDR_USER_LOGGEDON_PDU ? "true" : "false");
				break;
			}

			case CAP_DRIVE_TYPE:
				CWLOG_DBG(TAG, "received CAP_DRIVE_TYPE");
				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH);
				break;

			case CAP_PRINTER_TYPE:
				CWLOG_DBG(TAG, "received CAP_PRINTER_TYPE:");
				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH);
				break;

			case CAP_PORT_TYPE:
				CWLOG_DBG(TAG, "received CAP_PORT_TYPE");
				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH);
				break;

			case CAP_SMARTCARD_TYPE:
				CWLOG_DBG(TAG, "received CAP_SMARTCARD_TYPE");
				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH);
				break;

			default:
				CWLOG_WRN(TAG, "received unknown capablity type 0x%08X", capabilityType);
				s.seek(capabilityLength - RDPDR_CAPABILITY_HEADER_LENGTH);
		}
	}

	return true;
}

bool RDPDrChannelServer::receiveDeviceListAnnounceRequest(RdpStreamBuffer &s) {
	QMutexLocker locker(mMainLock);
	CWLOG_DBG(TAG, "receiving device list announce request");

	if (!s.verifyRemainingLength(4)) {
		return false;
	}

	quint32 deviceCount;
	quint32 deviceType;
	quint32 deviceId;
	quint32 deviceDataLength;
	QByteArray deviceData;
	quint32 deviceStatus;
	QString deviceName;
	char bufDosName[9];
	bufDosName[8] = 0;

	s >> deviceCount;

	CWLOG_DBG(TAG, "deviceCount: %u", deviceCount);

	for (int i = 0; i < deviceCount; i++)
	{
		if (!s.verifyRemainingLength(20)) {
			return false;
		}

		deviceStatus = STATUS_SUCCESS;

		s >> deviceType; /* DeviceType (4 bytes) */
		s >> deviceId; /* DeviceId (4 bytes) */

		RdpDrDevice *dev = NULL;

		RdpDrDevicesIterator iter = mDevices.find(deviceId);
		if (iter != mDevices.end()) {
			if (!iter.value()->disabled) {
				/*
				 * Note: MS-RDPEFS 3.2.5.1.9 / MS-RDPEFS 3.3.5.2.1
				 * This packet MUST contain only devices that have not been announced by
				 * previous Client Device List Announce packets.
				 * If this message contains DeviceIds that were previously sent in a
				 * Client Device List Announce message and the DeviceIds have not been
				 * invalidated, the protocol MUST be terminated.
				 */
				CWLOG_ERR(TAG, "error: duplicated deviceId: %u - terminating protocol!", deviceId);
				return false;
			}
			dev = iter.value();
		} else {
			dev = new RdpDrDevice();
			mDevices[deviceId] = dev;
		}

		dev->setDefaultValues();

		memcpy(bufDosName, s.pointer(), 8);
		s.seek(8);  /* PreferredDosName (8 bytes) */
		/*
		 * MS-RDPEFS 2.2.1.3
		 * The following characters are considered invalid for the
		 * PreferredDosName field: <, >, ", /, \, |
		 * A column character, ":", is valid only when present at the end
		 * of the PreferredDosName field, otherwise it is also considered invalid.
		 * If any of these characters are present, the DR_CORE_DEVICE_ANNOUNC_RSP
		 * packet for this device (section 2.2.2.1) will be sent with
		 * STATUS_ACCESS_DENIED set in the ResultCode field.
		 */
		for (int n = 0; n < 8; n++) {
			if ( (n < 8 && bufDosName[n+1] && bufDosName[n] == ':')
				|| bufDosName[n] == '<'
				|| bufDosName[n] == '>'
				|| bufDosName[n] == '\"'
				|| bufDosName[n] == '/'
				|| bufDosName[n] == '\\'
				|| bufDosName[n] == '|' )
			{
				CWLOG_ERR(TAG, "error: invalid character in preferredDosName");
				deviceStatus = STATUS_ACCESS_DENIED;
				break;
			}
		}

		deviceName = QString(bufDosName);

		/**
		 * Verify that there is no duplicated device name.
		 * Microsoft mstsc bug: if the channel gets restarted in a mstsc session
		 * then the client will send n new duplicated disk devices if that disk
		 * was n times re-plugged during the session!!
		 */
		for (iter = mDevices.begin(); iter != mDevices.end(); ++iter) {
			if (iter.value()->type == deviceType && !iter.value()->disabled) {
				if (iter.value()->name == deviceName) {
					CWLOG_ERR(TAG, "error: duplicated device name");
					deviceStatus = STATUS_ACCESS_DENIED;
				}
				break;
			}
		}

		s >> deviceDataLength; /* DeviceDataLength (4 bytes) */

		if (!s.verifyRemainingLength(deviceDataLength)) {
			return false;
		}

		deviceData = QByteArray(s.pointer(), deviceDataLength);
		s.seek(deviceDataLength);

		dev->type = (DeviceRedirectionType)deviceType;
		dev->name = deviceName;
		dev->status = deviceStatus;
		dev->deviceData = deviceData;
		dev->id = deviceId;

		if (deviceStatus == STATUS_SUCCESS) {
			if (!addDevice(dev)) {
				return false;
			}
		}

		CWLOG_DBG(TAG, "new device id: %u name='%s' status: 0x%08X",
			dev->id, QCSTR(dev->name), dev->status);

		if (!sendDeviceAnnounceResponse(dev->id, dev->status)) {
			CWLOG_ERR(TAG, "error: sendDeviceAnnounceResponse failed");
			return false;
		}
	}

	return true;
}

bool RDPDrChannelServer::receiveDeviceListRemoveRequest(RdpStreamBuffer &s) {
	CWLOG_DBG(TAG, "receiving device list remove request");

	if (!s.verifyRemainingLength(4)) {
		return false;
	}

	quint32 deviceCount;

	s >> deviceCount;

	CWLOG_DBG(TAG, "deviceCount: %u", deviceCount);

	if (!s.verifyRemainingLength(deviceCount * 4)) {
		return false;
	}

	quint32 deviceId;

	/* The IDs specified in this array match the IDs specified in the Client
	 * Device List Announce (section 2.2.3.1) packet.
	 * Note The client can send the DR_DEVICELIST_REMOVE message for devices
	 * that are removed after a session is connected.
	 * The server can accept the DR_DEVICE_REMOVE message for any removed
	 * device, including file system and port devices.
	 * The server can also accept reused DeviceIds of devices that have been
	 * removed, providing the implementation uses the DR_DEVICE_REMOVE message
	 * to do so.
	 */

	/**
	 * Note: We never remove devices from the list (only on protocol termination)
	 * We just set the device to disabled.
	 */

	for (int i = 0; i < deviceCount; i++) {
		s >> deviceId;
		CWLOG_DBG(TAG, "deviceId: %u", deviceId);
		RdpDrDevicesIterator iter = mDevices.find(deviceId);
		if (iter == mDevices.end()) {
			CWLOG_ERR(TAG, "error: remove request for a device id %u that has never been announced", deviceId);
			return false;
		}

		if (iter.value()->disabled) {
			/**
			 * Note: The specification does not explicitely state if this is an
			 * error. mstsc will send remove requests for device ids that have
			 * already been removed previously.
			 * Example: plug in a usb thumb drive (G:), open mstsc and enable the
			 * the redirection of G: and enable the redirection of drives that are
			 * plugged in later.
			 * Initially device id 1(G:) is announced. Unplug the stick and id 1 is
			 * removed. Plug it in again and device id 2(G:) is announced. Unplug it
			 * and now two device ids get removed (1 and 2). The list keeps growing
			 * on subsequent plug/unplug operations ;)
			 * Conclusion: don't return false here
			 */
			CWLOG_WRN(TAG, "warning: remove request for disabled/removed device id %u", deviceId);
			continue;
		}

		if (!removeDevice(iter.value())) {
			return false;
		}
	}

	return true;
}

bool RDPDrChannelServer::receiveDeviceIoCompletion(RdpStreamBuffer &s) {
	QMutexLocker locker(mMainLock);
	CWLOG_DBG(TAG, "receiving device IO completion");

	if (!s.verifyRemainingLength(12)) {
		return false;
	}

	quint32 deviceId;
	quint32 completionId;
	quint32 ioStatus;

	s >> deviceId; /* DeviceId (4 bytes) */
	s >> completionId; /* CompletionId (4 bytes) */
	s >> ioStatus; /* IoStatus (4 bytes) */

	CWLOG_DBG(TAG, "deviceId:     %u", deviceId);
	CWLOG_DBG(TAG, "completionId: %u", completionId);
	CWLOG_DBG(TAG, "ioStatus:     0x%08X", ioStatus);

	RdpDrDevice *dev;
	RdpDrDevicesConstIterator devIter;

	DeviceResponse *rsp;
	DeviceResponsesIterator rspIter;

	/* find device for this  this response */
	if ((devIter = mDevices.find(deviceId)) == mDevices.end()) {
		CWLOG_ERR(TAG, "error: received device IO completion id for unknown device");
		return false;
	}
	dev = devIter.value();

	/* find response pointer in map (might not exist anymore if it was canceled or if it timed out) */
	if ((rspIter = mResponses.find(completionId)) == mResponses.end()) {
		CWLOG_WRN(TAG, "warning: discarding a device IO completion for a canceled or timed out response.");
		/* FIXME: we could call releaseCompletionId(completionId); here if it is really safe */
		return true;
	}
	rsp = rspIter.value();

	/* unlink response pointer from the map */
	mResponses.erase(rspIter);

	/* bug: the response should already have been unlinked from the map previously when it was canceled */
	if (dev->disabled) {
		CWLOG_ERR(TAG, "error: found pending response for disabled device");
		return false;
	}

	/* paranoid consistency check */
	if (rsp->deviceId != deviceId) {
		CWLOG_ERR(TAG, "error: device id mismatch in device io completion");
		return false;
	}

	/* update response io status */
	rsp->ioStatus = ioStatus;

	/* decode the response from the stream */
	if (!rsp->decode(s)) {
		CWLOG_ERR(TAG, "error: failed to decode device io completion response");
		rsp->signalCompletion(false);
		return false;
	}

	/* notify the io callback */
	rsp->signalCompletion(true);
	return true;
}



/******************************************************************************/

bool RDPDrChannelServer::addDriveDevice(RdpDrDevice *device) {
	/* MS-RDPEFS 2.2.1.3 and 2.2.3.1
	 * The drive name MUST be specified in the PreferredDosName
	 * field; however, if the drive name is larger than the
	 * allocated size of the PreferredDosName field, then the
	 * drive name MUST be truncated to fit.
	 *
	 * If the client supports DRIVE_CAPABILITY_VERSION_02 in the
	 * Drive Capability Set, then the full name MUST also be
	 * specified in the DeviceData field, as a null-terminated
	 * Unicode string. If the DeviceDataLength field is nonzero,
	 * the content of the PreferredDosName field is ignored.
	 *
	 * HOWEVER: Most clients including mstsc don't adhere to
	 * this spec (deviceData empty, no null termination, ascii
	 * instead of unicode ... unbelievable !!).
	 * Therefore the following code block is disabled for now
	 * and we have to live with the PreferredDosName.
	 */
#if 0
	quint32 deviceDataLength = device->deviceData.size();
	if (deviceDataLength) {
		const char *data = device->deviceData.constData();
		if (data[deviceDataLength-1] != 0 || data[deviceDataLength-2] != 0) {
			CWLOG_DBG(TAG, "error: invalid null termination in %s", __FUNCTION__);
			return false;
		}
		device.name = QString((const QChar *)data);
	}
#endif
	return mountDevice(device);
}

bool RDPDrChannelServer::addPrinterDevice(RdpDrDevice *device) {
	/* not implemented */
	device->status = STATUS_NOT_SUPPORTED;
	return true;
}

bool RDPDrChannelServer::addSerialDevice(RdpDrDevice *device) {
	/* not implemented */
	device->status = STATUS_NOT_SUPPORTED;
	return true;
}

bool RDPDrChannelServer::addParallelDevice(RdpDrDevice *device) {
	/* not implemented */
	device->status = STATUS_NOT_SUPPORTED;
	return true;
}

bool RDPDrChannelServer::addSmartCardDevice(RdpDrDevice *device) {
	if (device->name != "SCARD") {
		CWLOG_ERR(TAG, "error: invalid smart card device name");
		device->status = STATUS_ACCESS_DENIED;
		return false;
	}
	/* not implemented */
	device->status = STATUS_NOT_SUPPORTED;
	return true;
}

bool RDPDrChannelServer::addDevice(RdpDrDevice *device) {
	bool rv = true;

	switch (device->type)
	{
		case RDPDR_DTYP_FILESYSTEM:
			if (!mHaveDriveCapability) {
				device->status = STATUS_NOT_SUPPORTED;
			} else {
				rv = addDriveDevice(device);
			}
			break;

		case RDPDR_DTYP_PRINT:
			if (!mHavePrinterCapability) {
				device->status = STATUS_NOT_SUPPORTED;
			} else {
				rv = addPrinterDevice(device);
			}
			break;

		case RDPDR_DTYP_SERIAL:
			if (!mHavePrinterCapability) {
				device->status = STATUS_NOT_SUPPORTED;
				break;
			} else {
				rv = addSerialDevice(device);
			}
			break;

		case RDPDR_DTYP_PARALLEL:
			if (!mHavePortCapability) {
				device->status = STATUS_NOT_SUPPORTED;
				break;
			} else {
				rv = addParallelDevice(device);
			}
			break;

		case RDPDR_DTYP_SMARTCARD:
			if (!mHaveSmartCardCapability) {
				device->status = STATUS_NOT_SUPPORTED;
				break;
			} else {
				rv = addSmartCardDevice(device);
			}
			break;

		default:
			device->status = STATUS_NOT_SUPPORTED;
			CWLOG_WRN(TAG, "warning: unknown device type %u", device->type);
			break;
	}

	return rv;
}

bool RDPDrChannelServer::removeDriveDevice(RdpDrDevice *device) {
	bool rv = true;
	FuseThread *ft = (FuseThread*)device->context;
	if (ft) {
		rv = ft->unmount();
		device->context = NULL;
		delete ft;
	}
	return rv;
}

bool RDPDrChannelServer::removePrinterDevice(RdpDrDevice *device) {
	/* not implemented */
	return true;
}

bool RDPDrChannelServer::removeSerialDevice(RdpDrDevice *device) {
	/* not implemented */
	return true;
}

bool RDPDrChannelServer::removeParallelDevice(RdpDrDevice *device) {
	/* not implemented */
	return true;
}

bool RDPDrChannelServer::removeSmartCardDevice(RdpDrDevice *device) {
	/* not implemented */
	return true;
}

bool RDPDrChannelServer::removeDevice(RdpDrDevice *device) {
	/* Must only be called from main thread */
	QMutexLocker locker(mMainLock);
	bool removed = false;

	CWLOG_DBG(TAG, "removing device id: %u (%s)", device->id, QCSTR(device->name));

	/* disable the device in order to discard further io callacks and incoming completions */
	device->disabled = true;

	/* cancel pending responses for this device and unlink them from the map */
	DeviceResponsesIterator iter = mResponses.begin();
	while (iter != mResponses.end()) {
		if (iter.value()->deviceId == device->id) {
			CWLOG_WRN(TAG, "remove device: canceling pending response %s %u",
				QCSTR(iter.value()->responseName),
				iter.value()->completionId);
			iter.value()->signalCompletion(false);
			/* unlink this response from the map */
			mResponses.erase(iter++);
		} else {
			++iter;
		}
	}

	/**
	 * Release the lock so that the waiting device request threads can process
	 * the canceled replies.
	 * Otherwise the following device removals might deadlock because the
	 * devices will wait forever for the return of the running IO callbacks.
	 */

	locker.unlock();

	switch (device->type)
	{
		case RDPDR_DTYP_FILESYSTEM:
			removed = removeDriveDevice(device);
			break;
		case RDPDR_DTYP_PRINT:
			removed = removePrinterDevice(device);
			break;
		case RDPDR_DTYP_SERIAL:
			removed = removeSerialDevice(device);
			break;
		case RDPDR_DTYP_PARALLEL:
			removed = removeParallelDevice(device);
			break;
		case RDPDR_DTYP_SMARTCARD:
			removed = removeSmartCardDevice(device);
			break;
		default:
			removed = true;
	}

	return removed;
}

quint32 RDPDrChannelServer::getCompletionId() {
	QMutexLocker locker(mMainLock);
	if (reusableCompletionIds.isEmpty()) {
		return mNextCompletionId++;
	}
	return reusableCompletionIds.takeFirst();
}

void RDPDrChannelServer::releaseCompletionId(quint32 completionId) {
	QMutexLocker locker(mMainLock);
	reusableCompletionIds.append(completionId);
}

bool RDPDrChannelServer::mountDevice(RdpDrDevice *device) {
	QString mountDir(mMountPointRule);
	CWLOG_INF(TAG, "mount rule: [%s]", QCSTR(mountDir));

	if (!mountDir.contains("{DEVICENAME}")) {
		CWLOG_ERR(TAG, "error: mount rule must contain the {DEVICENAME} token!");
		return false;
	}

	mountDir.replace("{HOME}", QDir::homePath());
	mountDir.replace("{CLIENTNAME}", mClientComputerName);
	mountDir.replace("{SESSIONID}", QString::number(getSessionId()));
	mountDir.replace("{DEVICENAME}", device->name);
	mountDir.replace("//", "/");

	if (!mountDir.startsWith('/') || !mountDir.endsWith('/')) {
		CWLOG_ERR(TAG, "error: mount rule must resolve to an absolute path, starting and ending with '/'");
		return false;
	}

	FuseThread *ft = new FuseThread(this, device, mountDir);
	connect(ft, SIGNAL(finished()), this, SLOT(deviceContextStopped()));
	device->context = ft;
	device->disabled = false;
	ft->start();
	return true;
}

void RDPDrChannelServer::deviceContextStopped() {
	void *deviceContext = sender();

	for (RdpDrDevicesIterator it = mDevices.begin(); it != mDevices.end(); ++it) {
		if (!it.value()->disabled && it.value()->context == deviceContext) {
			removeDevice(it.value());
			return;
		}
	}
}

RDPDrChannelServer::DeviceResponse* RDPDrChannelServer::sendSynchronousDeviceRequest(DeviceRequest &request) {
	QMutexLocker locker(mMainLock);

	RdpStreamBuffer s;
	qint64 bytesWritten;
	request.completionId = getCompletionId();

	CWLOG_DBG(TAG, "sending device IO request %s %u",
		QCSTR(request.requestName),
		request.completionId);

	if (!request.encode(s)) {
		releaseCompletionId(request.completionId);
		return NULL;
	}
	s.sealLength();
	if ((bytesWritten = writeData(s.data(), s.length())) < 0) {
		releaseCompletionId(request.completionId);
		return NULL;
	}
	DeviceResponse *response = request.getResponseInstance();
	mResponses[request.completionId] = response;

	locker.unlock();

	response->waitForCompletion(mResponseTimeout);

	locker.relock();

	if (!response->arrived) {
		CWLOG_ERR(TAG, "warning: response canceled or timed out in %s", __FUNCTION__);

		delete response;

		/**
		 * If the response was canceled it got already unlinked from the map
		 * but if there was a timeout it is still linked so we always must
		 * try to unlink the response here
		 */
		mResponses.remove(request.completionId);

		/**
		 * don't release the completion id in this case !!
		 * it must not be reused until the timed out or canceled response
		 * has actually arrived or never again to be on the safe side
		 * see comment in receiveDeviceIoCompletion
		 */
		return NULL;
	}
	releaseCompletionId(request.completionId);
	return response;
}

/*****************************************************************************/

RDPDrChannelServer::FuseThread::FuseThread(RDPDrChannelServer *pChannel, RdpDrDevice *device, const QString &mountDir)
	: QThread()
	, mDevice(device)
	, mVirtualChannel(pChannel)
	, mFuseHandle(NULL)
	, mFuseCommHandle(NULL)
{
	userId = getuid();
	groupId = getgid();
	mMountPoint.setPath(mountDir);
}

RDPDrChannelServer::FuseThread::~FuseThread() {
	/* Wait for the fuse event loop thread to terminate */
	QMutexLocker lock(&mFuseLoopLock);
	/* destroy the FUSE handle, must be called after fuse_unmount */
	if (mFuseHandle) {
		fuse_destroy(mFuseHandle);
	}
}

void RDPDrChannelServer::FuseThread::run() {
	QMutexLocker lock(&mFuseLoopLock);
	fuse_operations fuseOperations;
	FILE *procHandle;
	struct mntent *mnt;
	bool dirHasRdpdrMount = false;
	bool dirIsUnderRdpdrMount = false;

	CWLOG_INF(TAG, "mount point: [%s]", QCSTR(mMountPoint.absolutePath()));

	/* clean up disconnected/unclean rdpdr mounts */
	if (!(procHandle = setmntent("/proc/mounts", "r"))) {
		CWLOG_ERR(TAG, "error: failed to open /proc/mounts");
		return;
	}
	while ((mnt = getmntent(procHandle))) {
		struct stat stbuf;
		int x;
		if (!mnt->mnt_fsname || !mnt->mnt_dir) {
			continue;
		}
		if (strcmp(mnt->mnt_fsname, "rdpdr")) {
			continue;
		}
		if (stat(mnt->mnt_dir, &stbuf) < 0) {
			if (errno == ENOTCONN) {
				/* disconnected fuse process */
				CWLOG_WRN(TAG, "warning: trying to unmount unclean rdpdrfs [%s]", mnt->mnt_dir);
				fuse_unmount(mnt->mnt_dir, NULL);
			}
			continue;
		}

		QString mntDir(mnt->mnt_dir);
		if (mMountPoint.absolutePath() == mntDir) {
			dirHasRdpdrMount = true;
			continue;
		}

		if (mMountPoint.absolutePath().startsWith(mntDir)) {
			dirIsUnderRdpdrMount = true;
		}
	}
	endmntent(procHandle);

	if (dirIsUnderRdpdrMount) {
		CWLOG_ERR(TAG, "error: cowardly refusing to mount on top of an existing rdpdr mount directory.");
		return;
	}

	if (dirHasRdpdrMount) {
		CWLOG_ERR(TAG, "error: there is already an active rdpdr mount at [%s]", QCSTR(mMountPoint.absolutePath())) ;
		return;
	}

	if (!mMountPoint.exists() && !mMountPoint.mkpath(".")) {
		CWLOG_ERR(TAG, "error: failed to create [%s]", QCSTR(mMountPoint.absolutePath()));
		return;
	}

	if (mMountPoint.count() > 2) {
		CWLOG_WRN(TAG, "error: mount point not empty [%s]", QCSTR(mMountPoint.absolutePath()));
		return;
	}


	const char *argv[] = { "rdpdr", "-ofsname=rdpdr", NULL };
	fuse_args fuseArguments = FUSE_ARGS_INIT(2, (char**)argv);

	const QByteArray cMountPointPath(mMountPoint.absolutePath().toUtf8());

	if (!(mFuseCommHandle = fuse_mount(cMountPointPath.data(), &fuseArguments))) {
		CWLOG_ERR(TAG, "error: fuse_mount failed at [%s]", QCSTR(mMountPoint.absolutePath()));
		return;
	}

	memset(&fuseOperations, 0, sizeof(fuseOperations));
	fuseOperations.open = fuse_open;
	fuseOperations.release = fuse_release;
	fuseOperations.getattr = fuse_getattr;
	fuseOperations.fgetattr = fuse_fgetattr;
	fuseOperations.releasedir = fuse_releasedir;
	fuseOperations.opendir = fuse_opendir;
	fuseOperations.readdir = fuse_readdir;
	fuseOperations.read = fuse_read;
	fuseOperations.write = fuse_write;
	fuseOperations.unlink = fuse_unlink;
	fuseOperations.mkdir = fuse_mkdir;
	fuseOperations.rmdir = fuse_rmdir;
	fuseOperations.truncate = fuse_truncate;
	fuseOperations.ftruncate = fuse_ftruncate;
	fuseOperations.create = fuse_create;
	fuseOperations.utimens = fuse_utimens;
	fuseOperations.rename = fuse_rename;
	fuseOperations.statfs = fuse_statfs;

	if (!(mFuseHandle = fuse_new(mFuseCommHandle, &fuseArguments, &fuseOperations, sizeof(fuseOperations), this))) {
		CWLOG_ERR(TAG, "error: fuse_new failed");
		fuse_unmount(cMountPointPath.data(), mFuseCommHandle);
		mFuseCommHandle = NULL;
		return;
	}

	CWLOG_DBG(TAG, "enter fuse loop for deviceId %u", mDevice->id);
	fuse_loop(mFuseHandle);
	CWLOG_DBG(TAG, "exit fuse loop for deviceId %u (device->disabled=%d)", mDevice->id, mDevice->disabled);
}

bool RDPDrChannelServer::FuseThread::unmount() {
	if (!mFuseCommHandle) {
		CWLOG_WRN(TAG, "not mounted: [%s]", QCSTR(mMountPoint.absolutePath()));
		return true;
	}
	/**
	 * Unmount and wait for fuse event loop termination
	 *
	 * Note: Using fuse_exit() to terminate the fuse event loop is not enough.
	 * We can be called from a different different thread and fuse_exit() just
	 * sets the exited flag in the internal fuse_session struct.
	 * The fuse_loop won't notice this until it gets triggered by some file
	 * system activity. Better use fuse_unmount() (in addition)
	 */

	CWLOG_DBG(TAG, "unmounting [%s]", QCSTR(mMountPoint.absolutePath()));
	fuse_exit(mFuseHandle);
	fuse_unmount(mMountPoint.absolutePath().toUtf8(), mFuseCommHandle);
	mFuseCommHandle = NULL;

	/**
	 * FIXME: Detect and handle the case if fuse_unmount failed
	 * Currently we will wait (and block the channel) in the lock below until
	 * all handles are closed.
	 */

	/* Wait for the fuse event loop thread to terminate */
	CWLOG_DBG(TAG, "waiting for fuse event loop termination ...");
	if (!mFuseLoopLock.tryLock(10 * 1000)) {
		CWLOG_WRN(TAG, "warning: fuse unmount is blocking channel!");
		CWLOG_WRN(TAG, "warning: please check for open files on [%s]", QCSTR(mMountPoint.absolutePath()));
		mFuseLoopLock.lock();
	}

	CWLOG_DBG(TAG, "fuse event loop terminated");

	CWLOG_DBG(TAG, "removing mount point path [%s]", QCSTR(mMountPoint.absolutePath()));
	mMountPoint.rmpath(".");

	mFuseLoopLock.unlock();
	return true;
}

#define ENTERFUSECALLBACK \
	if (mDevice->disabled)	{ \
		CWLOG_WRN(TAG, "%s: device disabled. returning io error", __FUNCTION__); \
		return -EIO; \
	} \

quint32 RDPDrChannelServer::FuseThread::fuseCommonGetAttr(quint32 fileId, struct stat *stbuf) {
	quint32 ntStatus = STATUS_UNSUCCESSFUL;

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_uid = userId;
	stbuf->st_gid = groupId;

	FS::BasicInformation basicInformation;
	FS::StandardInformation standardInformation;

	if ((ntStatus = getFileInformationData(fileId, basicInformation))) {
		CWLOG_DBG(TAG, "get FileBasicInformation failed with status 0x%08X", ntStatus);
		return ntStatus;
	}
	if ((ntStatus = getFileInformationData(fileId, standardInformation))) {
		CWLOG_DBG(TAG, "get FileStandardInformation failed with status 0x%08X", ntStatus);
		return ntStatus;
	}
#if 0
	CWLOG_DBG(TAG, "creationTime:   %s", QCSTR(basicInformation.creationTime.toString()));
	CWLOG_DBG(TAG, "lastAccessTime: %s", QCSTR(basicInformation.lastAccessTime.toString()));
	CWLOG_DBG(TAG, "lastWriteTime:  %s", QCSTR(basicInformation.lastWriteTime.toString()));
	CWLOG_DBG(TAG, "attributes:     0x%08X", basicInformation.fileAttributes);
	CWLOG_DBG(TAG, "directory:      %d", standardInformation.directory);
	CWLOG_DBG(TAG, "allocationSize: %l", standardInformation.allocationSize);
	CWLOG_DBG(TAG, "endOfFile:      %d", standardInformation.endOfFile);
	CWLOG_DBG(TAG, "numberOfLinks:  %u", standardInformation.numberOfLinks);
	CWLOG_DBG(TAG, "deletePending:  %d", standardInformation.deletePending);
#endif

	stbuf->st_atime = basicInformation.lastAccessTime.toLocalTime().toTime_t();
	stbuf->st_mtime = basicInformation.lastWriteTime.toLocalTime().toTime_t();
	stbuf->st_ctime = basicInformation.creationTime.toLocalTime().toTime_t();

	FS::setStatFileMode(basicInformation.fileAttributes, stbuf);

	stbuf->st_nlink = standardInformation.numberOfLinks;

#if 0
	if (basicInformation.fileAttributes & FS::FileAttributeDirectory && stbuf->st_nlink < 2) {
		/**
		 * FIXME: The rdp client did not set the number of subdirectories.
		 * We must calculate st_nlink manually
		 */
	}
#endif

	stbuf->st_size = standardInformation.endOfFile;
	stbuf->st_blocks = standardInformation.allocationSize / 512;

	return ntStatus;
}

int RDPDrChannelServer::FuseThread::fuseGetAttr(const char *path, struct stat *stbuf) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s]", __FUNCTION__, mDevice->id, path);

#ifdef USE_STAT_CACHE
	if (mStatCache.get(path, stbuf)) {
		return 0;
	}
#endif

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileReadAttributes),
			FS::CreateOptions(0),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	ntStatus = fuseCommonGetAttr(fileId, stbuf);

#ifdef USE_STAT_CACHE
	if (!IS_ERROR(ntStatus)) {
		mStatCache.add(path, stbuf);
	}
#endif /* USE_STAT_CACHE */

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseFGetAttr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu", __FUNCTION__, mDevice->id, path, fi->fh);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId(fi->fh);

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	ntStatus = fuseCommonGetAttr(fileId, stbuf);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseReleaseDir(const char *path, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu", __FUNCTION__, mDevice->id, path, fi->fh);

	quint32 fileId(fi->fh);

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	quint32 ntStatus = closeHandle(fileId);

	if (!IS_ERROR(ntStatus)) {
		fi->fh = -1;
	}
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseOpenDir(const char *path, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu", __FUNCTION__, mDevice->id, path, fi->fh);

	FS::DesiredAccess desiredAccess = FS::DesiredAccess(0);
	FS::CreateOptions createOptions = FS::CreateOptions(FS::FileDirectoryFile);
	FS::CreateDisposition createDisposition = FS::CreateDisposition(FS::FileOpen);
	FS::FileAttribute attributes = FS::FileAttribute(0);

	quint32 ntStatus;
	quint32 fileId = 0;

	switch (fi->flags & O_ACCMODE) {
		case O_RDONLY:
			desiredAccess = FS::DesiredAccess(
								FS::FileListDirectory |
								FS::FileTraverse |
								FS::FileReadAttributes |
								FS::GenericRead);
			break;
		case O_WRONLY:
			desiredAccess = FS::DesiredAccess(
								FS::FileAddFile |
								FS::FileAddSubdirectory |
								FS::FileDeleteChild |
								FS::FileWriteAttributes |
								FS::GenericWrite);
			break;
		case O_RDWR:
			desiredAccess = FS::DesiredAccess(
								FS::FileListDirectory |
								FS::FileAddFile |
								FS::FileAddSubdirectory |
								FS::FileDeleteChild |
								FS::GenericRead |
								FS::GenericWrite);
			break;
		default:
			return -EINVAL;
	}

	if ((ntStatus = createHandle(path,
			desiredAccess,
			FS::CreateOptions(FS::FileDirectoryFile),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	fi->fh = fileId;
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseReadDir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu offset: %zd", __FUNCTION__, mDevice->id, path, fi->fh, offset);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId(fi->fh);

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	QString filterString(path);
	if (!filterString.endsWith('/')) {
		filterString.append('/');
	}

	filterString = toWindowsSeparators(filterString.append("*"));

	FS::BothDirectoryInformation bothDirectoryInformation;

	while (!(ntStatus = getDirectoryInformationData(fileId, filterString, bothDirectoryInformation))) {
		filterString.clear();
		QString *fileName = &bothDirectoryInformation.fileName;
		if (fileName->isEmpty()) {
			fileName = &bothDirectoryInformation.shortName;
		}
		if (fileName->isEmpty()) {
			CWLOG_ERR(TAG, "error: neither long nor short filename received in %s!", __FUNCTION__);
			continue;
		}

#ifdef USE_STAT_CACHE

		struct stat stbuf;
		memset(&stbuf, 0, sizeof(struct stat));
		stbuf.st_uid = userId;
		stbuf.st_gid = groupId;
		stbuf.st_atime = bothDirectoryInformation.lastAccessTime.toLocalTime().toTime_t();
		stbuf.st_mtime = bothDirectoryInformation.lastWriteTime.toLocalTime().toTime_t();
		stbuf.st_ctime = bothDirectoryInformation.creationTime.toLocalTime().toTime_t();

		FS::setStatFileMode(bothDirectoryInformation.fileAttributes, &stbuf);

		stbuf.st_nlink = 1;
		stbuf.st_size = bothDirectoryInformation.endOfFile;
		stbuf.st_blocks = bothDirectoryInformation.allocationSize / 512;

		QString cacheName(path);
		if (!cacheName.endsWith('/')) {
			cacheName.append('/');
		}
		cacheName.append(*fileName);
		mStatCache.add(cacheName, &stbuf);

		filler(buf, fileName->toUtf8().constData(), &stbuf, 0);

#else

		filler(buf, fileName->toUtf8().constData(), NULL, 0);

#endif /* USE_STAT_CACHE */

	}

	if (ntStatus == STATUS_NO_MORE_FILES) {
		ntStatus = STATUS_SUCCESS;
	} else {
		CWLOG_WRN(TAG, "warning: failed to retrieve bothDirectoryInformation. status: 0x%08X", ntStatus);
	}

out:
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseStatfs(const char *path, struct statvfs *stvfs) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s]", __FUNCTION__, mDevice->id, path);

	quint32 ntStatus;

	FS::FsAttributeInformation fsAttributeInformation;
	if ((ntStatus = getVolumeInformationData(fsAttributeInformation))) {
		CWLOG_ERR(TAG, "%s: get FsAttributeInformation failed with status 0x%08X", __FUNCTION__, ntStatus);
		return convertNtStatus(ntStatus);
	}
#if 0
	CWLOG_DBG(TAG, "maximumComponentNameLength:     %d", fsAttributeInformation.maximumComponentNameLength);
	CWLOG_DBG(TAG, "fileSystemName:                 %s", QCSTR(fsAttributeInformation.fileSystemName));
#endif

	FS::FsFullSizeInformation fsFullSizeInformation;
	if ((ntStatus = getVolumeInformationData(fsFullSizeInformation))) {
		CWLOG_ERR(TAG, "%s: get FsFullSizeInformation failed with status 0x%08X", __FUNCTION__, ntStatus);
		return convertNtStatus(ntStatus);
	}
#if 0
	CWLOG_DBG(TAG, "actualAvailableAllocationUnits: %l", fsFullSizeInformation.actualAvailableAllocationUnits);
	CWLOG_DBG(TAG, "callerAvailableAllocationUnits: %l", fsFullSizeInformation.callerAvailableAllocationUnits);
	CWLOG_DBG(TAG, "bytesPerSector:                 %u", fsFullSizeInformation.bytesPerSector);
	CWLOG_DBG(TAG, "sectorsPerAllocationUnit:       %u", fsFullSizeInformation.sectorsPerAllocationUnit);
	CWLOG_DBG(TAG, "totalAllocationUnits:           %l", fsFullSizeInformation.totalAllocationUnits);
#endif

#if 0
	FS::FsVolumeInformation fsVolumeInformation;
	if ((ntStatus = getVolumeInformationData(fsVolumeInformation))) {
		CWLOG_ERR(TAG, "%s: get FsVolumeInformation failed with status 0x%08X", __FUNCTION__, ntStatus);
		return convertNtStatus(ntStatus);
	}
	CWLOG_DBG(TAG, "volumeCreationTime:             %s", QCSTR(fsVolumeInformation.volumeCreationTime.toString()));
	CWLOG_DBG(TAG, "volumeLabel:                    %s", QCSTR(fsVolumeInformation.volumeLabel));
	CWLOG_DBG(TAG, "volumeSerialNumber:             %u", fsVolumeInformation.volumeSerialNumber);
#endif

	stvfs->f_bsize   = fsFullSizeInformation.bytesPerSector;
	stvfs->f_frsize  = fsFullSizeInformation.sectorsPerAllocationUnit * stvfs->f_bsize;
	stvfs->f_blocks  = fsFullSizeInformation.totalAllocationUnits;
	stvfs->f_bfree   = fsFullSizeInformation.actualAvailableAllocationUnits;
	stvfs->f_bavail  = fsFullSizeInformation.callerAvailableAllocationUnits;

	stvfs->f_namemax = fsAttributeInformation.maximumComponentNameLength;

	stvfs->f_files   = stvfs->f_blocks / 4; /* Hack */
	stvfs->f_ffree   = stvfs->f_bfree  / 4; /* Hack */
	stvfs->f_favail  = stvfs->f_bavail / 4; /* Hack */

	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseRename(const char *path, const char *newPath) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] newPath: [%s]", __FUNCTION__, mDevice->id, path, newPath);

	quint32 ntStatus;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileWriteData | FS::FileWriteAttributes | FS::GenericWrite),
			FS::CreateOptions(0),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	FS::RenameInformation renameInformation;
	renameInformation.replaceIfExists = true;
	renameInformation.fileName = toWindowsSeparators(newPath);

	ntStatus = setFileInformationData(fileId, renameInformation);

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseUtimens(const char *path, const struct timespec times[2]) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] atime: %lld.%ld mtime: %lld.%ld",
		__FUNCTION__, mDevice->id, path,
		times[0].tv_sec, times[0].tv_nsec,
		times[1].tv_sec, times[1].tv_nsec);

	/**
	 * Note from man man 2 utimensat
	 * times[0] specifies the new "last access time" (atime)
	 * times[1] specifies the new "last modification time" (mtime)	 *
	 * Each of the elements of times specifies a time as the number of seconds
	 * and nanoseconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
	 */

	quint32 ntStatus;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileWriteAttributes),
			FS::CreateOptions(FS::FileNonDirectoryFile),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	FS::BasicInformation basicInformation;
	FS::toQDateTime(times[0], basicInformation.lastAccessTime);
	FS::toQDateTime(times[1], basicInformation.lastWriteTime);
	FS::toQDateTime(times[1], basicInformation.changeTime);

	if ((ntStatus = setFileInformationData(fileId, basicInformation))) {
		CWLOG_ERR(TAG, "%s: set FileBasicInformation failed with status 0x%08X", __FUNCTION__, ntStatus);
	}

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseCreate(const char *path, mode_t mode, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu mode: %o", __FUNCTION__, mDevice->id, path, fi->fh, mode);

	/* don't allow special files */
	if (!S_ISREG(mode)) {
		return -EPERM;
	}

	quint32 ntStatus;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileWriteData | FS::FileWriteAttributes | FS::GenericWrite),
			FS::CreateOptions(FS::FileNonDirectoryFile),
			FS::CreateDisposition(FS::FileCreate),
			FS::FileAttribute(FS::FileAttributeNormal),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	fi->fh = fileId;
	return convertNtStatus(ntStatus);
}

quint32 RDPDrChannelServer::FuseThread::fuseCommonTruncate(quint32 fileId, off_t offset) {
	FS::EndOfFileInformation endOfFileInformation(offset);
	return setFileInformationData(fileId, endOfFileInformation);
}

int RDPDrChannelServer::FuseThread::fuseFTruncate(const char *path, off_t offset, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu offset: %zd", __FUNCTION__, mDevice->id, path, fi->fh, offset);

	quint32 fileId(fi->fh);

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	return convertNtStatus(fuseCommonTruncate(fileId, offset));
}

int RDPDrChannelServer::FuseThread::fuseTruncate(const char *path, off_t offset) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] offset: %zd", __FUNCTION__, mDevice->id, path, offset);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileWriteData | FS::FileWriteAttributes | FS::GenericWrite),
			FS::CreateOptions(FS::FileNonDirectoryFile),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	ntStatus = fuseCommonTruncate(fileId, offset);

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseRmDir(const char *path) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s]", __FUNCTION__, mDevice->id, path);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::Delete),
			FS::CreateOptions(FS::FileDirectoryFile),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	FS::DispositionInformation dispositionInformation;
	dispositionInformation.deletePending = true;

	ntStatus = setFileInformationData(fileId, dispositionInformation);

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}


int RDPDrChannelServer::FuseThread::fuseMkDir(const char *path, mode_t mode) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] mode: %o", __FUNCTION__, mDevice->id, path, mode);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::FileWriteAttributes),
			FS::CreateOptions(FS::FileDirectoryFile),
			FS::CreateDisposition(FS::FileCreate),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseUnlink(const char *path) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s]", __FUNCTION__, mDevice->id, path);

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	quint32 fileId = 0;

	if ((ntStatus = createHandle(path,
			FS::DesiredAccess(FS::Delete),
			FS::CreateOptions(FS::FileNonDirectoryFile),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	FS::DispositionInformation dispositionInformation;
	dispositionInformation.deletePending = true;

	ntStatus = setFileInformationData(fileId, dispositionInformation);

	closeHandle(fileId);
	return convertNtStatus(ntStatus);
}


int RDPDrChannelServer::FuseThread::fuseWrite(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu size: %zu offset: %zd",
		__FUNCTION__, mDevice->id, path, fi->fh, size, offset);

	quint32 fileId(fi->fh);
	int result = 0;

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	DeviceWriteResponse *response = NULL;
	DeviceWriteRequest request(mDevice->id, fileId, offset, size, buf);

	if (!(response = (DeviceWriteResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return -EIO;
	}
	if (response->ioStatus) {
		CWLOG_WRN(TAG, "warning: device write request for [%s] failed with status 0x%08X", path, response->ioStatus);
		result = convertNtStatus(response->ioStatus);
	} else {
		result = response->bufferLength;
	}
	delete(response);
	return result;
}

int RDPDrChannelServer::FuseThread::fuseRead(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu size: %zu offset: %zd",
		__FUNCTION__, mDevice->id, path, fi->fh, size, offset);

	quint32 fileId(fi->fh);
	int result = 0;

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	DeviceReadResponse *response = NULL;
	DeviceReadRequest request(mDevice->id, fileId, offset, size, buf);

	if (!(response = (DeviceReadResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return -EIO;
	}
	if (response->ioStatus) {
		CWLOG_WRN(TAG, "warning: device read request for [%s] failed with status 0x%08X", path, response->ioStatus);
		result = convertNtStatus(response->ioStatus);
	} else {
		if (response->bufferLength > size) {
			CWLOG_ERR(TAG, "error: maximum read length exceeded in read response");
			result = -EIO;
		} else {
			memcpy(buf, response->buffer, response->bufferLength);
			result = response->bufferLength;
		}
	}
	delete(response);
	return result;
}


int RDPDrChannelServer::FuseThread::fuseOpen(const char *path, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu flags: 0x%08X",
		__FUNCTION__, mDevice->id, path, fi->fh, fi->flags);

	FS::DesiredAccess desiredAccess = FS::DesiredAccess(0);

	quint32 ntStatus;
	quint32 fileId = 0;

	/**
	 * Note:
	 * No creation (O_CREAT, O_EXCL) and by default also no truncation (O_TRUNC) flags will be passed to open().
	 */

	switch (fi->flags & O_ACCMODE) {
		case O_RDONLY:
			desiredAccess = FS::DesiredAccess(
								FS::FileReadData |
								FS::FileReadAttributes |
								FS::GenericRead);
			break;
		case O_WRONLY:
			desiredAccess = FS::DesiredAccess(
								FS::FileWriteData |
								FS::FileWriteAttributes |
								FS::GenericWrite);
			break;
		case O_RDWR:
			desiredAccess = FS::DesiredAccess(
								FS::FileReadData |
								FS::FileWriteData |
								FS::FileReadAttributes |
								FS::GenericRead |
								FS::GenericWrite);
			break;
		default:
			return -EINVAL;
	}

	if ((ntStatus = createHandle(path,
			desiredAccess,
			FS::CreateOptions(0),
			FS::CreateDisposition(FS::FileOpen),
			FS::FileAttribute(0),
			fileId)))
	{
		return convertNtStatus(ntStatus);
	}

	fi->fh = fileId;
	return convertNtStatus(ntStatus);
}

int RDPDrChannelServer::FuseThread::fuseRelease(const char *path, struct fuse_file_info *fi) {
	ENTERFUSECALLBACK;
	CWLOG_DBG(TAG, "%s: dev: %u path: [%s] fh: %lu", __FUNCTION__, mDevice->id, path, fi->fh);

	quint32 fileId(fi->fh);

	if (!fileId) {
		CWLOG_ERR(TAG, "error: null file handle in %s", __FUNCTION__);
		return -EINVAL;
	}

	quint32 ntStatus = closeHandle(fileId);

	if (!IS_ERROR(ntStatus)) {
		fi->fh = -1;
	}
	return convertNtStatus(ntStatus);
}

quint32 RDPDrChannelServer::FuseThread::createHandle(const QString &path,
		const FS::DesiredAccess &desiredAccess,	const FS::CreateOptions &createOptions,
		const FS::CreateDisposition &createDisposition, const FS::FileAttribute &attributes,
		quint32 &fileId)
{
	/* See http://msdn.microsoft.com/en-us/library/bb432380(v=vs.85).aspx */

	quint32 ntStatus = STATUS_UNSUCCESSFUL;
	fileId = 0;
	//FS::Information dispositionInformation;

	DeviceCreateResponse *response = NULL;
	DeviceCreateRequest request(mDevice->id);

	request.path = toWindowsSeparators(path);

	request.desiredAccess = desiredAccess;
	request.fileAttributes = attributes;
	request.createDisposition = createDisposition;
	request.createOptions = FS::CreateOptions(FS::FileSynchronousIoNonalert | createOptions);
	request.sharedAccess = FS::SharedAccess(FS::FileShareRead | FS::FileShareWrite | FS::FileShareDelete);

	/* Workaround for rdesktop who incorrectly reads desiredAccess as big endian */

	if (mVirtualChannel->mIsBuggyRdesktop) {
		quint32 desiredAccess = request.desiredAccess;
		request.desiredAccess = qbswap(desiredAccess);
	}

	if (!(response = (DeviceCreateResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		CWLOG_ERR(TAG, "error: createHandle failed to retrieve device response");
		return ntStatus;
	}

	//dispositionInformation = FS::Information(response->information);
	fileId = response->fileId;
	if ((ntStatus = response->ioStatus)) {
		CWLOG_DBG(TAG, "error: createHandle failed with status 0x%08X", ntStatus);
	}

	delete(response);
	return ntStatus;
}

quint32 RDPDrChannelServer::FuseThread::closeHandle(quint32 &fileId)
{
	quint32 ntstatus = STATUS_UNSUCCESSFUL;
	DeviceCloseResponse *response = NULL;
	DeviceCloseRequest request(mDevice->id, fileId);

	if (!(response = (DeviceCloseResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return ntstatus;
	}
	ntstatus = response->ioStatus;
	delete(response);

	return ntstatus;
}

quint32 RDPDrChannelServer::FuseThread::setFileInformationData(quint32 fileId, FS::FileInformationData &data) {
	DriveSetInformationResponse *response = NULL;
	DriveSetInformationRequest request(mDevice->id, fileId, data);

	if (!(response = (DriveSetInformationResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return STATUS_UNSUCCESSFUL;
	}
	quint32 ntStatus = response->ioStatus;
	delete response;
	return ntStatus;
}

quint32 RDPDrChannelServer::FuseThread::getFileInformationData(quint32 fileId, FS::FileInformationData &data) {
	DriveQueryInformationResponse *response = NULL;
	DriveQueryInformationRequest request(mDevice->id, fileId, data);

	if (!(response = (DriveQueryInformationResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return STATUS_UNSUCCESSFUL;
	}
	quint32 ntStatus = response->ioStatus;
	delete response;
	return ntStatus;
}

quint32 RDPDrChannelServer::FuseThread::getDirectoryInformationData(quint32 fileId, const QString &path, FS::FileInformationData &data) {
	DriveQueryDirectoryResponse *response = NULL;
	DriveQueryDirectoryRequest request(mDevice->id, fileId, path, data);

	if (!(response = (DriveQueryDirectoryResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return STATUS_UNSUCCESSFUL;
	}
	quint32 ntStatus = response->ioStatus;
	delete response;
	return ntStatus;
}

quint32 RDPDrChannelServer::FuseThread::getVolumeInformationData(FS::VolumeInformationData &data) {
	DriveQueryVolumeInformationResponse *response = NULL;
	DriveQueryVolumeInformationRequest request(mDevice->id, data);

	if (!(response = (DriveQueryVolumeInformationResponse*)mVirtualChannel->sendSynchronousDeviceRequest(request))) {
		return STATUS_UNSUCCESSFUL;
	}
	quint32 ntStatus = response->ioStatus;
	delete response;
	return ntStatus;
}

QString RDPDrChannelServer::FuseThread::toWindowsSeparators(const QString &path) {
        QString wpath(path);
        wpath.replace("\\", "\\\\");
        wpath.replace("/", "\\");
        return wpath;
}

int RDPDrChannelServer::FuseThread::convertNtStatus(quint32 ntstatus) {
	switch (ntstatus >> 30) {
		case STATUS_SEVERITY_SUCCESS:		/* 0x0xxxxxxx */
			switch(ntstatus) {
				case STATUS_SUCCESS:                return 0;
				case STATUS_NOTIFY_ENUM_DIR:        return 0;
			}
			CWLOG_WRN(TAG, "warning: unhandled success status 0x%08X", ntstatus);
			return 0;


		case STATUS_SEVERITY_INFORMATIONAL:	/* 0x4xxxxxxx */
			CWLOG_WRN(TAG, "warning: unhandled informational status 0x%08X", ntstatus);
			return 0;


		case STATUS_SEVERITY_WARNING:		/* 0x8xxxxxxx */
			switch(ntstatus) {
				case (quint32)STATUS_NO_MORE_FILES:          return -ENOENT;
				case (quint32)STATUS_DEVICE_BUSY:            return -EBUSY;
			}
			CWLOG_WRN(TAG, "warning: unhandled warning status 0x%08X", ntstatus);
			return -EIO;


		case STATUS_SEVERITY_ERROR:			/* 0xCxxxxxxx */
			switch(ntstatus) {
				case (quint32)STATUS_UNSUCCESSFUL:           return -EINVAL;
				case (quint32)STATUS_DEVICE_BUSY:            return -EBUSY;
				case (quint32)STATUS_NOT_IMPLEMENTED:        return -ENOSYS;
				case (quint32)STATUS_INVALID_INFO_CLASS:     return -EINVAL;
				case (quint32)STATUS_INVALID_HANDLE:         return -EBADF;
				case (quint32)STATUS_INVALID_PARAMETER:      return -EINVAL;
				case (quint32)STATUS_NO_SUCH_DEVICE:         return -ENODEV;
				case (quint32)STATUS_NO_SUCH_FILE:           return -ENOENT;
				case (quint32)STATUS_INVALID_DEVICE_REQUEST: return -EINVAL;
				case (quint32)STATUS_END_OF_FILE:            return -ENODATA;
				case (quint32)STATUS_ACCESS_DENIED:          return -EACCES;
				case (quint32)STATUS_OBJECT_NAME_COLLISION:  return -EEXIST;
				case (quint32)STATUS_SHARING_VIOLATION:      return -EBUSY;
				case (quint32)STATUS_DISK_FULL:              return -ENOSPC;
				case (quint32)STATUS_FILE_IS_A_DIRECTORY:    return -EISDIR;
				case (quint32)STATUS_NOT_SUPPORTED:          return -ENOTSUP;
				case (quint32)STATUS_FILE_CORRUPT_ERROR:     return -ETIMEDOUT;
				case (quint32)STATUS_CANCELLED:              return -ETIMEDOUT;
				case (quint32)STATUS_OBJECT_PATH_NOT_FOUND:  return -ENODEV;
			}
			CWLOG_WRN(TAG, "warning: unhandled error status 0x%08X", ntstatus);
			return -EIO;

		default:
			CWLOG_ERR(TAG, "error mapping nstatus 0x%08X", ntstatus);
	}

	return -EIO;
}
