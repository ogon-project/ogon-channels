/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * RDP Stream Buffer Qt Class
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

#ifndef RDPSTREAMBUFFER_H
#define RDPSTREAMBUFFER_H

#include <QDataStream>
#include <QByteArray>
#include <QThread>

class RdpStreamBuffer {

public:
	RdpStreamBuffer() {
		mStream = new QDataStream(&mBuffer, QIODevice::ReadWrite);
		mStream->setByteOrder(QDataStream::LittleEndian);
		mLength = 0;
		mRequiredLengthError = 0;
	}

	~RdpStreamBuffer() {
		delete mStream;
	}

	void sealLength(quint64 length) {
		mLength = length;
	}
	void sealLength() {
		mLength = position();
	}
	quint64 length() const {
		return mLength;
	}
	quint64 remainingLength() const {
		quint64 pos = position();
		if (mLength > pos) {
			return mLength - pos;
		} else {
			return 0;
		}
	}
	bool verifyRemainingLength(quint64 len) {
		bool ok(remainingLength() >= len);
		if (!ok) {
			mRequiredLengthError = position() + len;
		} else {
			mRequiredLengthError = 0;
		}
		return ok;
	}
	quint64 requiredLengthError(void) {
		return mRequiredLengthError;
	}
	void setRequiredLengthError(const quint64 &len) {
		mRequiredLengthError = len;
	}
	const char *data() const {
		return mBuffer.constData();
	}
	const char *pointer() const {
		return mBuffer.constData()+position();
	}
	void setPosition(quint64 absulutePosition) {
		mStream->device()->seek(absulutePosition);
	}
	quint64 position() const {
		return mStream->device()->pos();
	}
	void seek(quint64 relativePosition) {
		quint64 newPosition = position() + relativePosition;
		mStream->device()->seek(newPosition);
	}
	void rewind(quint64 relativePosition) {
		quint64 currentPosition = position();
		if (relativePosition > currentPosition) {
			setPosition(0);
		} else {
			setPosition(currentPosition - relativePosition);
		}
	}
	bool reserveRemainingCapacity(quint64 size) {
		quint64 pos = position();
		quint64 tmpPosition = pos + size;
		if (!mStream->device()->seek(tmpPosition)) {
			return false;
		}
		return mStream->device()->seek(pos);
	}
	const QByteArray toHex(quint32 length=0) {
		return mBuffer.left(length == 0 ? mLength : length).toHex();
	}
	void clear() {
		mRequiredLengthError = 0;
		mBuffer.clear();
		setPosition(0);
		sealLength();
	}
	void writeUnicodeString(const QString &data, bool includingNull = true) {
		if (data.length()) {
			mStream->writeRawData((const char*)(data.unicode()), data.length()*2);
		}
		if (includingNull) {
			*mStream << quint16(0);
		}
	}
	bool readUnicodeString(QString &data, quint32 numberOfBytes) {
		if (numberOfBytes < 2 || numberOfBytes % 2) {
			return false;
		}
		if (!verifyRemainingLength(numberOfBytes)) {
			return false;
		}
		quint32 maxChars = numberOfBytes / 2;
		quint16 *ubuffer = (quint16*)pointer();
		if (*(ubuffer + maxChars -1) == 0) {
			data = QString((const QChar *)ubuffer, -1);
		} else {
			data = QString((const QChar *)ubuffer, maxChars);
		}
		seek(numberOfBytes);
		return true;
	}
	void write(const char *data, int len) {
		mStream->writeRawData(data, len);
	}
	void write(quint8 u) {
		*mStream << u;
	}
	void write(qint8 u) {
		*mStream << u;
	}
	void write(quint16 u) {
		*mStream << u;
	}
	void write(qint16 u) {
		*mStream << u;
	}
	void write(quint32 u) {
		*mStream << u;
	}
	void write(qint32 u) {
		*mStream << u;
	}
	void write(quint64 u) {
		*mStream << u;
	}
	void write(qint64 u) {
		*mStream << u;
	}
	void read(quint8 &u) {
		*mStream >> u;
	}
	void read(qint8 &u) {
		*mStream >> u;
	}
	void read(quint16 &u) {
		*mStream >> u;
	}
	void read(qint16 &u) {
		*mStream >> u;
	}
	void read(quint32 &u) {
		*mStream >> u;
	}
	void read(qint32 &u) {
		*mStream >> u;
	}
	void read(quint64 &u) {
		*mStream >> u;
	}
	void read(qint64 &u) {
		*mStream >> u;
	}
	RdpStreamBuffer &operator<<(quint8 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(qint8 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(quint16 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(qint16 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(quint32 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(qint32 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(quint64 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(qint64 u) {
		*mStream << u;
		return *this;
	}
	RdpStreamBuffer &operator<<(const QByteArray &b) {
		mStream->writeRawData(b.constData(), b.size());
		return *this;
	}
	RdpStreamBuffer &operator>>(quint8 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(qint8 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(quint16 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(qint16 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(quint32 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(qint32 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(quint64 &u) {
		*mStream >> u;
		return *this;
	}
	RdpStreamBuffer &operator>>(qint64 &u) {
		*mStream >> u;
		return *this;
	}

private:
	quint64 mRequiredLengthError;
	quint64 mLength;
	QByteArray mBuffer;
	QDataStream *mStream;
};

#endif /* RDPSTREAMBUFFER_H */
