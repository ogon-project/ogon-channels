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

#include <QThread>
#include <ogon-channels/qt/rdpchannelserver.h>
#include <ogon-channels/logging.h>

/* native includes for os specific process instance locking */
#if !defined(_WIN32)
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#define TAG CWLOG_TAG("server")

RDPChannelServer::RDPChannelServer(HANDLE serverHandle, quint32 sessionId, const QString &channelName, bool showProtocol, QObject *parent)
	: RDPSessionNotification(parent)
	, mServerHandle(serverHandle)
	, mSessionId(sessionId)
	, mChannelName(channelName)
	, mShowProtocol(showProtocol)
	, mSocketNotifier(NULL)
	, mInitOk(false)
	, mChannelHandle(INVALID_HANDLE_VALUE)
	, mChannelFileHandle(INVALID_HANDLE_VALUE)
	, mChannelFileDescriptor(-1)
	, mStarted(false)
	, mIsDynamic(false)
{
	if (mChannelName.isEmpty()) {
		CWLOG_FTL(TAG, "an empty channel name was specified");
		abort();
		return;
	}

	if (mServerHandle != WTS_CURRENT_SERVER) {
		CWLOG_FTL(TAG, "only WTS_CURRENT_SERVER is currently supported");
		return;
	}

	if (mSessionId == WTS_CURRENT_SESSION) {
		LPWSTR buffer;
		DWORD size;
		ULONG id;
		if (!WTSQuerySessionInformationW(mServerHandle,	WTS_CURRENT_SESSION,
				WTSSessionId, &buffer, &size))
		{
			CWLOG_ERR(TAG, "failed to query current session id");
			return;
		}
		id = *(ULONG *)buffer;
		WTSFreeMemory(buffer);
		mSessionId = id;
	}

	mInitOk = true;
}

RDPChannelServer::~RDPChannelServer() {
	if (mStarted) {
		stop();
	}
}

void RDPChannelServer::sessionChange(Status status, quint32 sessionId)
{
	CWLOG_DBG(TAG, "status changed to %s", statusString(status));

	switch(status) {
		case RDPSessionNotification::WtsRemoteConnect:
			start();
			break;
		case RDPSessionNotification::WtsRemoteDisconnect:
			stop();
			break;
		/* we don't care about the rest */
		case RDPSessionNotification::WtsConsoleConnect:
		case RDPSessionNotification::WtsConsoleDisconnect:
		case RDPSessionNotification::WtsSessionLogon:
		case RDPSessionNotification::WtsSessionLogoff:
		case RDPSessionNotification::WtsSessionLock:
		case RDPSessionNotification::WtsSessionUnlock:
		case RDPSessionNotification::WtsSessionRemoteControl:
		case RDPSessionNotification::WtsSessionCreate:
		case RDPSessionNotification::WtsSessionTerminate:
			break;
	}
}

bool RDPChannelServer::isInitOk() {
	return mInitOk;
}

bool RDPChannelServer::isStarted() {
	return mStarted;
}

bool RDPChannelServer::lockApplicationInstance() {
	quint32 uid = getuid();
	quint32 sid = getSessionId();

#if defined(_WIN32)
	/**
	 * create a global mutex:
	 * use the prefix "Global\" to explicitly create the object in the global namespace
	 */
	return false; /* FIXME: implement */

#elif defined(__linux__)
	/**
	 * creata a unix socket in the abstract name space:
	 * sun_path[0] is a null byte
	 */
	int len;
	int sock;
	struct sockaddr_un addr;


	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
			CWLOG_ERR(TAG, "failed to create unix socket");
			return false;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;

	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "%s#%u#%u",
		mChannelName.toLatin1().constData(), uid, sid);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path + 1) + 1;
	CWLOG_DBG(TAG, "binding abstract socket '%s'", &addr.sun_path[1]);
	if (bind(sock, (struct sockaddr *)&addr, len) != 0) {
			return false;
	}

#else
	/**
	 * create a lock file in the temporary directory and set an advisory
	 * file lock of size 1 at the session id offset
	 */

	int fd;
	struct flock fl;
	char lockfile[1024];

	snprintf(lockfile, sizeof(lockfile), "%s/.%s.%u.%u.lock",
		P_tmpdir, mChannelName.toLatin1().constData(), uid, sid);

	CWLOG_DBG(TAG, "opening lock file '%s'", lockfile);
	if ((fd = open(lockfile, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
			WLog_ERR("error creating lockfile '%s'", lockfile);
			return false;
	}

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_len = 1;
	fl.l_start = sid;

	if ((fcntl(fd, F_SETLK, &fl) != 0)) {
			return false;
	}
#endif

	return true;
}

bool RDPChannelServer::start() {
	if (!mInitOk) {
		CWLOG_ERR(TAG, "error, cannot start if initialization failed");
		return false;
	}

	if (mStarted) {
		CWLOG_ERR(TAG, "error, channel is already started");
		return false;
	}

	mChannelHandle = WTSVirtualChannelOpenEx(mSessionId, mChannelName.toLatin1().data(), mIsDynamic ?  WTS_CHANNEL_OPTION_DYNAMIC : 0);

	if (!mChannelHandle || mChannelHandle == INVALID_HANDLE_VALUE) {
		mChannelHandle = INVALID_HANDLE_VALUE;
		CWLOG_ERR(TAG, "WTSVirtualChannelOpen failed");
		return false;
	}

	PVOID vcFileHandlePtr = NULL;
	DWORD vcQueryLen;

	if (!WTSVirtualChannelQuery(mChannelHandle, WTSVirtualFileHandle,
			&vcFileHandlePtr, &vcQueryLen))
	{
		CWLOG_ERR(TAG, "WTSVirtualChannelQuery failed");
		WTSVirtualChannelClose(mChannelHandle);
		mChannelHandle = INVALID_HANDLE_VALUE;
		return false;
	}
	memcpy(&mChannelFileHandle, vcFileHandlePtr, sizeof(mChannelFileHandle));
	WTSFreeMemory(vcFileHandlePtr);

	mLastChunk = false;

	if (mShowProtocol) {
		mBytesRequired = sizeof(CHANNEL_PDU_HEADER);
	} else {
		mBytesRequired = CHANNEL_CHUNK_LENGTH;
	}

#ifndef WIN32
	mChannelFileDescriptor = GetNamePipeFileDescriptor(mChannelFileHandle);
	if (mChannelFileDescriptor < 0) {
		WTSVirtualChannelClose(mChannelHandle);
		mChannelHandle = INVALID_HANDLE_VALUE;
		return false;
	}
	mSocketNotifier = new QSocketNotifier(mChannelFileDescriptor, QSocketNotifier::Read);
	connect(mSocketNotifier, SIGNAL(activated(int)), this, SLOT(channelReadReady()));
#else
	/* TODO */
#endif

	mStarted = true;
	return true;
}

bool RDPChannelServer::stop() {
	if (!mStarted) {
		return false;
	}

#ifndef WIN32
	disconnect(mSocketNotifier, SIGNAL(activated(int)), this, SLOT(channelReadReady()));
	delete mSocketNotifier;
	mSocketNotifier = NULL;
#else
	/* TODO */
#endif

	WTSVirtualChannelClose(mChannelHandle);
	mChannelHandle = INVALID_HANDLE_VALUE;
	mStarted = false;
	mStream.clear();
	return true;
}


void RDPChannelServer::channelReadReady() {
	//CWLOG_VRB(TAG, "mBytesRequired: %u", mBytesRequired);
	if (!mStarted) {
		CWLOG_ERR(TAG, "internal error: channel not started");
		return;
	}

	if (mBytesRequired == 0) {
		CWLOG_ERR(TAG, "internal error: no data required");
		goto err;
	}

	qint64 bytesReturned;

	if (!mStream.reserveRemainingCapacity(mBytesRequired)) {
		goto err;
	}

	bytesReturned = readData((char *)mStream.pointer(), mBytesRequired);
	CWLOG_VRB(TAG, "bytesReturned: %ld mBytesRequired: %u", bytesReturned, mBytesRequired);
	if (bytesReturned < 1) {
		CWLOG_ERR(TAG, "readData unexpectedly returned %d", bytesReturned);
		goto err;
	}
	mStream.seek(bytesReturned);

	if (!mShowProtocol) {
		mStream.sealLength();
		mStream.setPosition(0);
		mStream.setRequiredLengthError(0);

		if (!processReceivedData(mStream)) {
			/* check if processReceivedData only failed because if insufficient stream length */
			if (mStream.requiredLengthError()) {
				if (mStream.requiredLengthError() <= mStream.length()) {
					CWLOG_ERR(TAG, "internal error: stream length should have been sufficient");
					goto err;
				}
				mBytesRequired = mStream.requiredLengthError() - mStream.length();
				mStream.setPosition(mStream.length());
				return;
			}
			CWLOG_ERR(TAG, "processReceivedData failed 1");
			goto err;
		}
		mStream.clear();
		mBytesRequired = CHANNEL_CHUNK_LENGTH;
		return;
	}

	mBytesRequired -= bytesReturned;

	if (mBytesRequired > 0) {
		return;
	}

	/* we have received all required bytes for now */
	if (mLastChunk) {
		if (mStream.position() != mDataLength) {
			CWLOG_ERR(TAG, "channel protocol failure 2");
			goto err;
		}

		mStream.sealLength();
		mStream.setPosition(0);

		if (!processReceivedData(mStream)) {
			CWLOG_ERR(TAG, "processReceivedData failed 2");
			goto err;
		}

		mStream.clear(); /* FIXME: check if this has any performance impact */

		mLastChunk = false;
		mBytesRequired = sizeof(CHANNEL_PDU_HEADER);
		return;
	}

	/* the stream position is now after a new channel pdu header */
	quint32 length;
	quint32 flags;

	/* read the channel pdu header, 8 bytes */
	mStream.rewind(8);
	mStream >> length; /* uint32 length, 4 bytes */
	mStream >> flags; /* uint32 flags, 4 bytes */

	if (length == 0) {
		CWLOG_ERR(TAG, "channel protocol failure 3");
		goto err;
	}

	/* length must not change between related chunks */
	if (flags & CHANNEL_FLAG_FIRST) {
		mDataLength = length;
	} else if (mDataLength != length) {
		CWLOG_ERR(TAG, "channel protocol failure 4");
		goto err;
	}

	/* we overwrite the pdu header bytes in our stream buffer */
	mStream.rewind(8);

	mLastChunk = (flags & CHANNEL_FLAG_LAST) ? true : false;

	if (mStream.position() >= length) {
		CWLOG_ERR(TAG, "channel protocol failure 5");
		goto err;
	}

	if (flags & CHANNEL_FLAG_FIRST) {
		mStream.setPosition(0);
	}

	if (CHANNEL_CHUNK_LENGTH < (length - mStream.position())) {
		mBytesRequired = CHANNEL_CHUNK_LENGTH;
	} else {
		mBytesRequired = length - mStream.position();
	}

	mBytesRequired += mLastChunk ? 0 : sizeof(CHANNEL_PDU_HEADER);

	return;

err:
	stop();
}

qint64 RDPChannelServer::readData(char *data, quint32 maxSize) {
	BOOL status;
	ULONG bytesReturned;

	if (!mStarted) {
		CWLOG_ERR(TAG, "readData called in stopped channel");
		return -1;
	}

	status = WTSVirtualChannelRead(mChannelHandle, 0, (PCHAR)data, maxSize, &bytesReturned);

	if (!status) {
		CWLOG_ERR(TAG, "WTSVirtualChannelRead failed");
		return -1;
	}

	return bytesReturned;
}

qint64 RDPChannelServer::writeData(const RdpStreamBuffer &stream, quint32 maxSize)
{
	if (maxSize == 0) {
		maxSize = stream.length();
	}

	//CWLOG_VRB(TAG, "writeData: [%s]", ((RdpStreamBuffer&)stream).toHex().constData());

	return writeData(stream.data(), maxSize);
}

qint64 RDPChannelServer::writeData(const char *data, quint32 maxSize) {
	ULONG bytesWritten;
	qint64 bytesWrittenTotal = 0;

	if (!mStarted) {
		CWLOG_ERR(TAG, "writeData called in stopped channel");
		return -1;
	}

	/**
	 * Note: MSDN does not say if WTSVirtualChannelWrite is blocking or not.
	 * until that is clarified we assume that it should be blocking and make
	 * sure that the behavior is the same if it is not.
	 */

	while (WTSVirtualChannelWrite(mChannelHandle, (PCHAR)data,
			maxSize - bytesWrittenTotal, &bytesWritten))
	{
		bytesWrittenTotal += bytesWritten;
		if (bytesWrittenTotal > maxSize) {
			CWLOG_ERR(TAG, "detected WTSVirtualChannelWrite bug");
			return -1;
		}
		if (bytesWrittenTotal == maxSize) {
			return bytesWrittenTotal;
		}
		bytesWritten = 0;
		QThread::msleep(10);
	}

	CWLOG_ERR(TAG, "WTSVirtualChannelWrite failed");
	return -1;
}

void RDPChannelServer::setIsDynamic(bool dynamic) {
	mIsDynamic = dynamic;
}

bool RDPChannelServer::getIsDynamic() {
	return mIsDynamic;
}
