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

#ifndef RDPDRCHANNELSERVER_H
#define RDPDRCHANNELSERVER_H

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

#include <ogon-channels/logging.h>

#include <ogon-channels/qt/rdpchannelserver.h>
#include <ogon-channels/qt/rdpsessionnotification.h>
#include <ogon-channels/qt/unixsignalhandler.h>

/* #define USE_STAT_CACHE */

#define FUSE_USE_VERSION 26
#include <fuse.h>

#define RDPDR_HEADER_LENGTH                     4
#define RDPDR_CAPABILITY_HEADER_LENGTH          8

#define TAG CWLOG_TAG("rdpdr")

class RDPDrChannelServer : public RDPChannelServer {
	Q_OBJECT

public:
	RDPDrChannelServer(QCoreApplication *app, bool useSessionNotification, QObject *parent = 0);
	virtual ~RDPDrChannelServer();
	virtual bool start();
	virtual bool stop();
	bool setMountPointRule(const QString &rule);
	bool setResponseTimeout(quint32 ms);

private:
	QMutex* mMainLock;

	quint32 mResponseTimeout;

	QString mClientComputerName;
	QString mMountPointRule;

	bool mUseSessionNotification;
	quint32 mClientId;
	bool mSendUserLoggedOnPdu;
	bool mHavePrinterCapability;
	bool mHavePortCapability;
	bool mHaveDriveCapability;
	bool mHaveSmartCardCapability;
	bool mIsBuggyRdesktop;
	QList<quint32> reusableCompletionIds;
	quint32 mNextCompletionId;

	virtual bool processReceivedData(RdpStreamBuffer &stream);
	virtual void sessionChange(Status status, quint32 sessionId);

	bool processPDU(RdpStreamBuffer &stream);
	quint32 getPduSize(RdpStreamBuffer &stream);

	bool sendAnnounceRequest();
	bool sendCoreCapabilityRequest();
	bool sendClientIdConfirm();
	bool sendUserLoggedOn();
	bool sendDeviceAnnounceResponse(quint32 deviceId, quint32 resultCode);

	bool receiveAnnounceReply(RdpStreamBuffer &s);
	bool receiveNameRequest(RdpStreamBuffer &s);
	bool receiveCoreCapabilityResponse(RdpStreamBuffer &s);
	bool receiveDeviceListAnnounceRequest(RdpStreamBuffer &s);
	bool receiveDeviceListRemoveRequest(RdpStreamBuffer &s);
	bool receiveDeviceIoCompletion(RdpStreamBuffer &s);

	enum DeviceRedirectionType {
		RDPDR_DTYP_UNKNOWN      = 0x00000000,
		RDPDR_DTYP_SERIAL       = 0x00000001,
		RDPDR_DTYP_PARALLEL     = 0x00000002,
		RDPDR_DTYP_PRINT        = 0x00000004,
		RDPDR_DTYP_FILESYSTEM   = 0x00000008,
		RDPDR_DTYP_SMARTCARD    = 0x00000020,
	};

	/**
	 * FIXME: Make RdpDrDevice and created subclasses for
	 * RdpDriveDevcie, RdpPrinterDevice, etc
	 */

	class RdpDrDevice {
	public:
		RdpDrDevice() {
			setDefaultValues();
		}
		void setDefaultValues() {
			id = 0;
			type = RDPDR_DTYP_UNKNOWN;
			status = STATUS_ACCESS_DENIED;
			disabled = true;
			context = NULL;
			name.clear();
		}
		quint32 id;
		DeviceRedirectionType type;
		QString name;
		QByteArray deviceData;
		quint32 status;
		bool disabled;
		void *context;
	};

	typedef QMap<int, RdpDrDevice*> RdpDrDevices;
	typedef RdpDrDevices::iterator RdpDrDevicesIterator;
	typedef RdpDrDevices::const_iterator RdpDrDevicesConstIterator;
	RdpDrDevices mDevices;

	quint32 getCompletionId();
	void releaseCompletionId(quint32 completionId);

	class DeviceRequest;
	class DeviceResponse;

	typedef QMap<quint32, DeviceResponse*> DeviceResponses;
	typedef DeviceResponses::iterator DeviceResponsesIterator;
	typedef DeviceResponses::const_iterator DeviceResponsesConstIterator;

	DeviceResponses mResponses;

	DeviceResponse* sendSynchronousDeviceRequest(DeviceRequest &request);

	bool addDevice(RdpDrDevice *device);
	bool removeDevice(RdpDrDevice *device);
	bool addDriveDevice(RdpDrDevice *device);
	bool addPrinterDevice(RdpDrDevice *device);
	bool addSerialDevice(RdpDrDevice *device);
	bool addParallelDevice(RdpDrDevice *device);
	bool addSmartCardDevice(RdpDrDevice *device);
	bool removeDriveDevice(RdpDrDevice *device);
	bool removePrinterDevice(RdpDrDevice *device);
	bool removeSerialDevice(RdpDrDevice *device);
	bool removeParallelDevice(RdpDrDevice *device);
	bool removeSmartCardDevice(RdpDrDevice *device);

	enum ProtocolState {
		ProtocolStateInit                           = 0,
		ProtocolStateWaitingAnnounceReply           = 1,
		ProtocolStateWaitingNameRequest             = 2,
		ProtocolStateWaitingCapabilityResponse      = 3,
		ProtocolStateRunning                        = 4,
	};

	ProtocolState mProtocolState;

	enum PacketId {
		PAKID_CORE_SERVER_ANNOUNCE      = 0x496E,
		PAKID_CORE_CLIENTID_CONFIRM     = 0x4343,
		PAKID_CORE_CLIENT_NAME          = 0x434E,
		PAKID_CORE_DEVICELIST_ANNOUNCE  = 0x4441,
		PAKID_CORE_DEVICE_REPLY         = 0x6472,
		PAKID_CORE_DEVICE_IOREQUEST     = 0x4952,
		PAKID_CORE_DEVICE_IOCOMPLETION  = 0x4943,
		PAKID_CORE_SERVER_CAPABILITY    = 0x5350,
		PAKID_CORE_CLIENT_CAPABILITY    = 0x4350,
		PAKID_CORE_DEVICELIST_REMOVE    = 0x444D,
		PAKID_CORE_USER_LOGGEDON        = 0x554C,
		PAKID_PRN_CACHE_DATA            = 0x5043,
		PAKID_PRN_USING_XPS             = 0x5543,
	};

	enum ComponentType {
		RDPDR_CTYP_CORE     = 0x4472,
		RDPDR_CTYP_PRN      = 0x5052,
	};

	enum CapabilityType {
		CAP_GENERAL_TYPE    = 0x0001,
		CAP_PRINTER_TYPE    = 0x0002,
		CAP_PORT_TYPE       = 0x0003,
		CAP_DRIVE_TYPE      = 0x0004,
		CAP_SMARTCARD_TYPE  = 0x0005,
	};

	enum GeneralCapabilityVersion {
		DRIVE_CAPABILITY_VERSION_01  = 0x00000001,
		DRIVE_CAPABILITY_VERSION_02  = 0x00000002,
	};

	enum GeneralCapabilityIrp {
		RDPDR_IRP_MJ_CREATE                             = 0x00000001,
		RDPDR_IRP_MJ_CLEANUP                            = 0x00000002,
		RDPDR_IRP_MJ_CLOSE                              = 0x00000004,
		RDPDR_IRP_MJ_READ                               = 0x00000008,
		RDPDR_IRP_MJ_WRITE                              = 0x00000010,
		RDPDR_IRP_MJ_FLUSH_BUFFERS                      = 0x00000020,
		RDPDR_IRP_MJ_SHUTDOWN                           = 0x00000040,
		RDPDR_IRP_MJ_DEVICE_CONTROL                     = 0x00000080,
		RDPDR_IRP_MJ_QUERY_VOLUME_INFORMATION           = 0x00000100,
		RDPDR_IRP_MJ_SET_VOLUME_INFORMATION             = 0x00000200,
		RDPDR_IRP_MJ_QUERY_INFORMATION                  = 0x00000400,
		RDPDR_IRP_MJ_SET_INFORMATION                    = 0x00000800,
		RDPDR_IRP_MJ_DIRECTORY_CONTROL                  = 0x00001000,
		RDPDR_IRP_MJ_LOCK_CONTROL                       = 0x00002000,
		RDPDR_IRP_MJ_QUERY_SECURITY                     = 0x00004000,
		RDPDR_IRP_MJ_SET_SECURITY                       = 0x00008000,
	};

	enum GeneralCapabilityPdu {
		RDPDR_DEVICE_REMOVE_PDUS                        = 0x00000001,
		RDPDR_CLIENT_DISPLAY_NAME_PDU                   = 0x00000002,
		RDPDR_USER_LOGGEDON_PDU                         = 0x00000004,
	};

	enum GeneralCapabilityExtraFlag {
		ENABLE_ASYNCIO  = 0x00000001,
	};

	class FS {
	public:
		enum DesiredAccess {
			/* See MS-SMB2 2.2.13.1.1 File_Pipe_Printer_Access_Mask */
			FileReadData                                = 0x00000001,
			FileWriteData                               = 0x00000002,
			FileAppendData                              = 0x00000004,
			FileReadEa                                  = 0x00000008,
			FileWriteEa                                 = 0x00000010,
			FileExecute                                 = 0x00000020,
			FileDeleteChild                             = 0x00000040,
			FileReadAttributes                          = 0x00000080,
			FileWriteAttributes                         = 0x00000100,
			Delete                                      = 0x00010000,
			ReadControl                                 = 0x00020000,
			WriteDac	                                = 0x00040000,
			WriteOwner                                  = 0x00080000,
			Synchronize                                 = 0x00100000,
			AccessSystemSecurity                        = 0x01000000,
			MaximumAllowed                              = 0x02000000,
			GenericAll                                  = 0x10000000,
			GenericExecute                              = 0x20000000,
			GenericWrite                                = 0x40000000,
			GenericRead                                 = 0x80000000,

			/* See MS-SMB2 2.2.13.1.2 Directory_Access_Mask */
			FileListDirectory                           = 0x00000001,
			FileAddFile			                        = 0x00000002,
			FileAddSubdirectory                         = 0x00000004,
			FileTraverse                                = 0x00000020,
		};

		enum FileAttribute {
			/* See MS-FSCC 2.6 */
			FileAttributeReadonly                       = 0x00000001,
			FileAttributeHidden                         = 0x00000002,
			FileAttributeSystem                         = 0x00000004,
			FileAttributeDirectory                      = 0x00000010,
			FileAttributeArchive                        = 0x00000020,
			FileAttributeNormal                         = 0x00000080,
			FileAttributeTemporary                      = 0x00000100,
			FileAttributeSpardeFile                     = 0x00000200,
			FileAttributeReparsePoint                   = 0x00000400,
			FileAttributeCompressed                     = 0x00000800,
			FileAttributeOffline                        = 0x00001000,
			FileAttributeNotContentIndexed              = 0x00002000,
			FileAttributeEncrypted                      = 0x00004000,
			FileAttributeIntegrityStream                = 0x00008000,
			FileAttributeNoScrubData                    = 0x00020000,
		};

		enum SharedAccess {
			/* See [MS-SMB2] 2.2.13 */
			FileShareRead                               = 0x00000001,
			FileShareWrite                              = 0x00000002,
			FileShareDelete                             = 0x00000004,
		};

		enum CreateDisposition {
			/* See [MS-SMB2] 2.2.13 */
			FileSupersede                               = 0x00000000,
			FileOpen                                    = 0x00000001,
			FileCreate                                  = 0x00000002,
			FileOpenIf                                  = 0x00000003,
			FileOverwrite                               = 0x00000004,
			FileOverwriteIf		                        = 0x00000005,
		};

		enum CreateOptions {
			/* See [MS-SMB2] 2.2.13 */
			FileDirectoryFile                           = 0x00000001,
			FileWriteThrough                            = 0x00000002,
			FileSequentialOnly                          = 0x00000004,
			FileNoIntermediateBuffering                 = 0x00000008,
			FileSynchronousIoAlert                      = 0x00000010,
			FileSynchronousIoNonalert                   = 0x00000020,
			FileNonDirectoryFile                        = 0x00000040,
			FileCompleteIfOplocked                      = 0x00000100,
			FileNoEaKnowledge                           = 0x00000200,
			FileRandomAccess                            = 0x00000800,
			FileDeleteOnClose                           = 0x00001000,
			FileOpenByFileid                            = 0x00002000,
			FileOpenForBackupIntent                     = 0x00004000,
			FileNoCompression                           = 0x00008000,
			FileOpenRemoteInstance                      = 0x00000400,
			FileOpenRequiringOplock                     = 0x00010000,
			FileDisallowExclusive                       = 0x00020000,
			FileReserveOpfilter                         = 0x00100000,
			FileOpenReparsePoint                        = 0x00200000,
			FileOpenNoRecall                            = 0x00400000,
			FileOpenForFreeSpaceQuery                   = 0x00800000,
		};

		enum Information {
			FileSuperseded                              = 0x00000000,
			FileOpened                                  = 0x00000001,
			FileOverwritten                             = 0x00000003,
		};

		enum FileSystemInformationClass {
			/* See [MS-FSCC] 2.5 */
			FileFsVolumeInformation                     = 0x00000001,
			FileFsLabelInformation                      = 0x00000002,
			FileFsSizeInformation                       = 0x00000003,
			FileFsDeviceInformation                     = 0x00000004,
			FileFsAttributeInformation                  = 0x00000005,
			FileFsControlInformation                    = 0x00000006,
			FileFsFullSizeInformation                   = 0x00000007,
			FileFsObjectIdInformation                   = 0x00000008,
			FileFsDriverPathInformation                 = 0x00000009,
			FileFsVolumeFlagsInformation                = 0x0000000A,
			FileFsSectorSizeInformation                 = 0x0000000B,
		};

		enum FileInformationClass {
			/* See [MS-FSCC] 2.4 */
			FileDirectoryInformation                    = 0x00000001,
			FileFullDirectoryInformation                = 0x00000002,
			FileBothDirectoryInformation                = 0x00000003,
			FileBasicInformation                        = 0x00000004,
			FileStandardInformation                     = 0x00000005,
			FileInternalInformation                     = 0x00000006,
			FileEaInformation                           = 0x00000007,
			FileAccessInformation                       = 0x00000008,
			FileNameInformation                         = 0x00000009,
			FileRenameInformation                       = 0x0000000A,
			FileLinkInformation                         = 0x0000000B,
			FileNamesInformation                        = 0x0000000C,
			FileDispositionInformation                  = 0x0000000D,
			FilePositionInformation                     = 0x0000000E,
			FileFullEaInformation                       = 0x0000000F,
			FileModeInformation                         = 0x00000010,
			FileAlignmentInformation                    = 0x00000011,
			FileAllInformation                          = 0x00000012,
			FileAllocationInformation                   = 0x00000013,
			FileEndOfFileInformation                    = 0x00000014,
			FileAlternateNameInformation                = 0x00000015,
			FileStreamInformation                       = 0x00000016,
			FilePipeInformation                         = 0x00000017,
			FilePipeLocalInformation                    = 0x00000018,
			FilePipeRemoteInformation                   = 0x00000019,
			FileMailslotQueryInformation                = 0x0000001A,
			FileMailslotSetInformation                  = 0x0000001B,
			FileCompressionInformation                  = 0x0000001C,
			FileObjectIdInformation                     = 0x0000001D,
			FileCompletionInformation                   = 0x0000001E,
			FileMoveClusterInformation                  = 0x0000001F,
			FileQuotaInformation                        = 0x00000020,
			FileReparsePointInformation                 = 0x00000021,
			FileNetworkOpenInformation                  = 0x00000022,
			FileAttributeTagInformation                 = 0x00000023,
			FileTrackingInformation                     = 0x00000024,
			FileIdBothDirectoryInformation              = 0x00000025,
			FileIdFullDirectoryInformation              = 0x00000026,
			FileValidDataLengthInformation              = 0x00000027,
			FileShortNameInformation                    = 0x00000028,
			FileIoCompletionNotificationInformation     = 0x00000029,
			FileIoStatusBlockRangeInformation           = 0x0000002A,
			FileIoPriorityHintInformation               = 0x0000002B,
			FileSfioReserveInformation                  = 0x0000002C,
			FileSfioVolumeInformation                   = 0x0000002D,
			FileHardLinkInformation                     = 0x0000002E,
			FileProcessIdsUsingFileInformation          = 0x0000002F,
			FileNormalizedNameInformation               = 0x00000030,
			FileNetworkPhysicalNameInformation          = 0x00000031,
			FileIdGlobalTxDirectoryInformation          = 0x00000032,
			FileIsRemoteDeviceInformation               = 0x00000033,
			FileAttributeCacheInformation               = 0x00000034,
			FileNumaNodeInformation                     = 0x00000035,
			FileStandardLinkInformation                 = 0x00000036,
			FileRemoteProtocolInformation               = 0x00000037,
			FileReplaceCompletionInformation            = 0x00000038,
			FileMaximumInformation                      = 0x00000039,
		};

		static void setStatFileMode(const FileAttribute &fileAttributes, struct stat *stbuf) {
			if (fileAttributes & FileAttributeDirectory)	{
				stbuf->st_mode = S_IFDIR | (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
			}
			else {
				stbuf->st_mode = S_IFREG | (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			}
			if (fileAttributes & FileAttributeReadonly) {
				stbuf->st_mode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
			}
		}

		static void toQDateTime(const qint64 &fileTime, QDateTime &qTime) {
			QDateTime origin(QDate(1601, 1, 1), QTime(0, 0, 0, 0), Qt::UTC);
			qTime = origin.addMSecs(fileTime / 10000);
		}

		static void toQDateTime(const struct timespec &ts, QDateTime &qTime) {
			QDateTime origin = QDateTime::fromTime_t(ts.tv_sec).toUTC();
			qTime = origin.addMSecs(ts.tv_nsec / 1000000);
		}

		static void toWindowsFileTime(const QDateTime &qTime, qint64 &fileTime) {
			if (!qTime.isValid()) {
				fileTime = 0;
			} else {
				QDateTime origin(QDate(1601, 1, 1), QTime(0, 0, 0, 0), Qt::UTC);
				fileTime = 10000 * origin.msecsTo(qTime);
			}
		}


		class VolumeInformationData {
		public:
			quint32 informationClass;

			VolumeInformationData() {
				informationClass = 0;
			}

			virtual ~VolumeInformationData() {	}

			virtual bool decode(RdpStreamBuffer &s) = 0;

			virtual bool encode(RdpStreamBuffer &s) = 0;

			virtual quint32 dataLength() = 0;

#if 0
			static VolumeInformationData* produce(quint32 infoClass) {
				switch(infoClass) {
					case FileFsVolumeInformation:
						return new FsVolumeInformation();
					case FileFsLabelInformation:
						return new FsLabelInformation();
					case FileFsSizeInformation:
						return new FsSizeInformation();
					case FileFsDeviceInformation:
						return new FsDeviceInformation();
					case FileFsAttributeInformation:
						return new FsAttributeInformation();
					case FileFsFullSizeInformation:
						return new FsFullSizeInformation();
				}
				CWLOG_ERR(TAG, "error: Unknown VolumeInformationData subclass: %u", infoClass);
				return NULL;
			}
#endif
		};

		/**
		 * MS-FSCC 2.5.9 FileFsVolumeInformation
		 */
		class FsVolumeInformation : public VolumeInformationData {
		public:
			QDateTime volumeCreationTime;
			quint32 volumeSerialNumber;
			bool supportsObjects;
			QString volumeLabel;

			FsVolumeInformation() {
				informationClass = FileFsVolumeInformation;
				volumeCreationTime = QDateTime::currentDateTimeUtc();
				volumeSerialNumber = 0;
				supportsObjects = false;
			}

			quint32 dataLength() {
				return (18 + volumeLabel.length() * 2);
			}

			bool encode(RdpStreamBuffer &s) {
				qint64 fileTime;
				toWindowsFileTime(volumeCreationTime, fileTime);
				s << fileTime; /* VolumeCreationTime (8 bytes) */
				s << volumeSerialNumber; /* VolumeSerialNumber (4 bytes) */
				s << quint32(volumeLabel.length() * 2); /* VolumeLabelLength (4 bytes) */
				s << quint8(supportsObjects ? 1 : 0); /* SupportsObjects (1 byte) */
				//s << quint8(0); /* Reserved (1 byte), seems to be missing in RDP */
				s.writeUnicodeString(volumeLabel, false);/* VolumeLabel (variable) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				quint32 volumeLabelLength;
				qint64  fileTime;
				quint8 boolValue;

				if (!s.verifyRemainingLength(18)) {
						return false;
				}
				s >> fileTime; /* CreationTime (8 bytes) */
				FS::toQDateTime(fileTime, volumeCreationTime);
				s >> volumeSerialNumber; /* VolumeSerialNumber (4 bytes) */
				s >> volumeLabelLength; /* VolumeLabelLength (4 bytes) */
				if (volumeLabelLength > 512 || volumeLabelLength % 2) {
					return false;
				}
				s >> boolValue; /* SupportsObjects (1 byte) */
				supportsObjects = boolValue;
				//s.seek(1); /* Reserved (1 byte), seems to be missing in RDP */
				if (volumeLabelLength && !s.readUnicodeString(volumeLabel, volumeLabelLength)) {
					return false;
				}
				return true;
			}
		};

		/**
		 * MS-FSCC 2.5.4 FileFsFullSizeInformation
		 */
		class FsFullSizeInformation : public VolumeInformationData {
		public:
			qint64 totalAllocationUnits;
			qint64 callerAvailableAllocationUnits;
			qint64 actualAvailableAllocationUnits;
			quint32 sectorsPerAllocationUnit;
			quint32 bytesPerSector;

			FsFullSizeInformation() {
				informationClass = FileFsFullSizeInformation;
				totalAllocationUnits = 0;
				callerAvailableAllocationUnits = 0;
				actualAvailableAllocationUnits = 0;
				bytesPerSector = 0;
			}

			quint32 dataLength() {
				return (32);
			}

			bool encode(RdpStreamBuffer &s) {
				s << totalAllocationUnits; /* TotalAllocationUnits (8 bytes) */
				s << callerAvailableAllocationUnits; /* CallerAvailableAllocationUnits (8 bytes) */
				s << actualAvailableAllocationUnits; /* ActualAvailableAllocationUnits (8 bytes) */
				s << sectorsPerAllocationUnit; /* SectorsPerAllocationUnit (4 bytes) */
				s << bytesPerSector; /* BytesPerSector (4 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(32)) {
						return false;
				}
				s >> totalAllocationUnits; /* TotalAllocationUnits (8 bytes) */
				s >> callerAvailableAllocationUnits; /* CallerAvailableAllocationUnits (8 bytes) */
				s >> actualAvailableAllocationUnits; /* ActualAvailableAllocationUnits (8 bytes) */
				s >> sectorsPerAllocationUnit; /* SectorsPerAllocationUnit (4 bytes) */
				s >> bytesPerSector; /* BytesPerSector (4 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.5.1 FileFsAttributeInformation
		 */
		class FsAttributeInformation : public VolumeInformationData {
		public:
			quint32 fileSystemAttributes;
			qint32 maximumComponentNameLength;
			QString fileSystemName;

			FsAttributeInformation() {
				informationClass = FileFsAttributeInformation;
				fileSystemAttributes = 0;
				maximumComponentNameLength = 0;
			}

			quint32 dataLength() {
				return (12 + fileSystemName.length() * 2);
			}

			bool encode(RdpStreamBuffer &s) {
				s << fileSystemAttributes; /* FileSystemAttributes (4 bytes) */
				s << maximumComponentNameLength; /* MaximumComponentNameLength (4 bytes) */
				s << quint32(fileSystemName.length() * 2); /* FileSystemNameLength (4 bytes) */
				s.writeUnicodeString(fileSystemName, false); /* FileSystemName (variable) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				quint32 fileSystemNameLength;

				if (!s.verifyRemainingLength(12)) {
						return false;
				}
				s >> fileSystemAttributes; /* FileSystemAttributes (4 bytes) */
				s >> maximumComponentNameLength; /* MaximumComponentNameLength (4 bytes): A 32-bit signed integer */
				s >> fileSystemNameLength; /* FileSystemNameLength (4 bytes) */
				if (fileSystemNameLength == 0 || fileSystemNameLength > 512 || fileSystemNameLength % 2) {
					CWLOG_ERR(TAG, "error: invalid fileSystemNameLength: %u", fileSystemNameLength);
					return false;
				}
				if (!s.readUnicodeString(fileSystemName, fileSystemNameLength)) {
					return false;
				}
				return true;
			}
		};

		/**
		 * MS-FSCC 2.5.10 FileFsDeviceInformation
		 */
		class FsDeviceInformation : public VolumeInformationData {
			/* WARNING: UNTESTED IMPLEMENTATION */
		public:
			quint32 deviceType;
			quint32 characteristics;

			FsDeviceInformation() {
				informationClass = FileFsDeviceInformation;
				deviceType = 0;
				characteristics = 0;
			}

			quint32 dataLength() {
				return 8;
			}

			bool encode(RdpStreamBuffer &s) {
				s << deviceType; /* DeviceType (4 bytes) */
				s << characteristics; /* Characteristics (4 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(8)) {
						return false;
				}
				s >> deviceType; /* DeviceType (4 bytes) */
				s >> characteristics; /* Characteristics (4 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.5.8 FileFsSizeInformation
		 */
		class FsSizeInformation : public VolumeInformationData {
		public:
			qint64 totalAllocationUnits;
			qint64 availableAllocationUnits;
			quint32 sectorsPerAllocationUnit;
			quint32 bytesPerSector;

			FsSizeInformation() {
				informationClass = FileFsSizeInformation;
				totalAllocationUnits = 0;
				availableAllocationUnits = 0;
				sectorsPerAllocationUnit = 0;
				bytesPerSector = 0;
			}

			quint32 dataLength() {
				return 24;
			}

			bool encode(RdpStreamBuffer &s) {
				s << totalAllocationUnits; /* TotalAllocationUnits (8 bytes) */
				s << availableAllocationUnits; /* AvailableAllocationUnits (8 bytes) */
				s << sectorsPerAllocationUnit; /* SectorsPerAllocationUnit (4 bytes) */
				s << bytesPerSector; /* BytesPerSector (4 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(24)) {
						return false;
				}
				s >> totalAllocationUnits; /* TotalAllocationUnits (8 bytes) */
				s >> availableAllocationUnits; /* AvailableAllocationUnits (8 bytes) */
				s >> sectorsPerAllocationUnit; /* SectorsPerAllocationUnit (4 bytes) */
				s >> bytesPerSector; /* BytesPerSector (4 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.5.5 FileFsLabelInformation
		 */
		class FsLabelInformation : public VolumeInformationData {
			/* WARNING: UNTESTED IMPLEMENTATION */
		public:
			QString volumeLabel;

			FsLabelInformation() {
				informationClass = FileFsLabelInformation;
			}

			quint32 dataLength() {
				return (volumeLabel.length() * 2);
			}

			bool encode(RdpStreamBuffer &s) {
				s << quint32(volumeLabel.length() * 2); /* FileSystemNameLength (4 bytes) */
				s.writeUnicodeString(volumeLabel, false); /* FileSystemName (variable) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				quint32 volumeLabelLength;

				if (!s.verifyRemainingLength(4)) {
						return false;
				}
				s >> volumeLabelLength; /* VolumeLabelLength (4 bytes) */
				if (volumeLabelLength > 512 || volumeLabelLength % 2) {
					return false;
				}
				if (volumeLabelLength && !s.readUnicodeString(volumeLabel, volumeLabelLength)) { /* FileName (variable) */
					return false;
				}
				return true;
			}
		};

		class FileInformationData {
		public:
			quint32 informationClass;
			QString informationClassName;

			FileInformationData() {
				informationClass = 0;
			}
			virtual ~FileInformationData() { }
			virtual bool decode(RdpStreamBuffer &s) {
				CWLOG_ERR(TAG, "error: missing decoder for FileinformationClass: %s", QCSTR(informationClassName));
				return false;
			}
			virtual bool encode(RdpStreamBuffer &s) {
				CWLOG_ERR(TAG, "error: missing encoder for FileinformationClass: %s", QCSTR(informationClassName));
				return false;
			}
			virtual quint32 dataLength() = 0;

#if 0
			static FileInformationData* produce(quint32 infoClass) {
				switch(infoClass) {
					case FileBasicInformation:
						return new BasicInformation();
					case FileStandardInformation:
						return new StandardInformation();
					case FileBothDirectoryInformation:
						return new BothDirectoryInformation();
					case FileDispositionInformation:
						return new DispositionInformation();
					case FileEndOfFileInformation:
						return new EndOfFileInformation();
					case FileRenameInformation:
						return new RenameInformation();
					case FileNamesInformation:
						return new NamesInformation();
					case FileAllocationInformation:
						return new AllocationInformation();
					case FileAttributeTagInformation:
						return new AttributeTagInformation();
				}
				CWLOG_ERR(TAG, "error: Unknown FileInformationData subclass: %u", infoClass);
				return NULL;
			}
#endif
		};
		/**
		 * MS-FSCC 2.4.34 FileRenameInformation
		 * MS-FSCC 2.4.34.2 FileRenameInformation for SMB2
		 */
		class RenameInformation : public FileInformationData {
		public:
			bool replaceIfExists;
			QString fileName;

			RenameInformation()
			{
				informationClass = FileRenameInformation;
				replaceIfExists = false;
				informationClassName = "FileRenameInformation";
			}

			quint32 dataLength() {
				return (6 + fileName.length() * 2);
			}

			bool encode(RdpStreamBuffer &s) {
				s << quint8(replaceIfExists ? 1 : 0); /* ReplaceIfExists (1 byte) */
				/* The 3-byte or 7-byte padding mentioned in MS-FSCC 2.4.34 does not seem to be used over RDP */
				s << quint8(0); /* RootDirectory (just 1 byte contrary to MS-FSCC 2.4.34) */
				s << quint32(fileName.length() * 2); /* VolumeLabelLength (4 bytes) */
				s.writeUnicodeString(fileName, false);/* VolumeLabel (variable) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.26 FileNamesInformation
		 */
		class NamesInformation : public FileInformationData {
			/* WARNING: UNTESTED IMPLEMENTATION */
		public:
			quint32 nextEntryOffset;
			quint32 fileIndex;
			QString fileName;

			NamesInformation() {
				informationClass = FileNamesInformation;
				nextEntryOffset = 0;
				fileIndex = 0;
				informationClassName = "NamesInformation";
			}

			quint32 dataLength() {
				return (12 + fileName.length() * 2);
			}

			bool encode(RdpStreamBuffer &s) {
				s << nextEntryOffset; /* NextEntryOffset (4 bytes) */
				s << fileIndex; /* FileIndex (4 bytes) */
				s << quint32(fileName.length() * 2); /* FileNameLength (4 bytes) */
				s.writeUnicodeString(fileName, false);/* VolumeLabel (variable) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				quint32 fileNameLength;

				if (!s.verifyRemainingLength(12)) {
						return false;
				}
				s >> nextEntryOffset; /* NextEntryOffset (4 bytes) */
				/* We don't support NextEntryOffset values other than 0 */
				if (nextEntryOffset) {
					CWLOG_ERR(TAG, "error: nextEntryOffset > 0 not implemented in NamesInformation class");
					return false;
				}
				s >> fileIndex; /* FileIndex (4 bytes) */
				s >> fileNameLength; /* FileNameLength (4 bytes) */
				if (fileNameLength > 512 || fileNameLength % 2) {
					return false;
				}
				if (fileNameLength && !s.readUnicodeString(fileName, fileNameLength)) { /* FileName (variable) */
					return false;
				}
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.4 FileAllocationInformation
		 */
		class AllocationInformation : public FileInformationData {
			/* WARNING: UNTESTED IMPLEMENTATION */
		public:
			qint64 allocationSize;

			AllocationInformation() {
				informationClass = FileAllocationInformation;
				allocationSize = 0;
				informationClassName = "AllocationInformation";
			}

			quint32 dataLength() {
				return 8;
			}

			bool encode(RdpStreamBuffer &s) {
				s << allocationSize; /* AllocationSize (8 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(8)) {
						return false;
				}
				s >> allocationSize; /* AllocationSize (8 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.6 FileAttributeTagInformation
		 */
		class AttributeTagInformation : public FileInformationData {
			/* WARNING: UNTESTED IMPLEMENTATION */
		public:
			FileAttribute fileAttributes;
			quint32 reparseTag;

			AttributeTagInformation() {
				informationClass = FileAttributeTagInformation;
				fileAttributes = FileAttribute(0);
				reparseTag = 0;
				informationClassName = "AttributeTagInformation";
			}

			quint32 dataLength() {
				return 8;
			}

			bool encode(RdpStreamBuffer &s) {
				s << quint32(fileAttributes); /* FileAttributes (4 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(8)) {
						return false;
				}
				quint32 attributes;
				s >> attributes; /* FileAttributes (4 bytes) */
				fileAttributes = FileAttribute(attributes);
				s >> reparseTag; /* ReparseTag (4 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.7 FileBasicInformation
		 */
		class BasicInformation : public FileInformationData	{
		public:
			QDateTime creationTime;
			QDateTime lastAccessTime;
			QDateTime lastWriteTime;
			QDateTime changeTime;
			FileAttribute fileAttributes;

			BasicInformation() {
				informationClass = FileBasicInformation;
				fileAttributes = FileAttribute(0);
				informationClassName = "BasicInformation";
			}

			quint32 dataLength() {
				return 36;
			}

			bool encode(RdpStreamBuffer &s) {
				qint64 fileTime;
				toWindowsFileTime(creationTime, fileTime);
				s << fileTime; /* CreationTime (8 bytes) */
				toWindowsFileTime(lastAccessTime, fileTime);
				s << fileTime; /* LastAccessTime (8 bytes) */
				toWindowsFileTime(lastWriteTime, fileTime);
				s << fileTime; /* LastWriteTime (8 bytes) */
				toWindowsFileTime(changeTime, fileTime);
				s << fileTime; /* ChangeTime (8 bytes) */
				s << quint32(fileAttributes); /* FileAttributes (4 bytes) */
				// The 4-byte padding mentioned in MS-FSCC 2.4.7 does not seem to be used over RDP
				// s.seek(4); /* Reserved (4 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(36)) {
						return false;
				}
				qint64  fileTime;
				quint32 attributes;

				s >> fileTime; /* CreationTime (8 bytes) */
				FS::toQDateTime(fileTime, creationTime);
				s >> fileTime; /* LastAccessTime (8 bytes) */
				FS::toQDateTime(fileTime, lastAccessTime);
				s >> fileTime; /* LastWriteTime (8 bytes) */
				FS::toQDateTime(fileTime, lastWriteTime);
				s >> fileTime; /* ChangeTime (8 bytes) */
				FS::toQDateTime(fileTime, changeTime);
				s >> attributes; /* FileAttributes (4 bytes) */
				fileAttributes = FileAttribute(attributes);
				// The 4-byte padding mentioned in MS-FSCC 2.4.7 does not seem to be used over RDP
				// s.seek(4); /* Reserved (4 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.38 FileStandardInformation
		 */
		class StandardInformation : public FileInformationData {
		public:
			qint64 allocationSize;
			qint64 endOfFile;
			quint32 numberOfLinks;
			bool deletePending;
			bool directory;

			StandardInformation() {
				informationClass = FileStandardInformation;
				allocationSize = 0;
				endOfFile = 0;
				numberOfLinks = 0;
				deletePending = false;
				directory = false;
				informationClassName = "StandardInformation";
			}

			quint32 dataLength() {
				return 22;
			}

			bool encode(RdpStreamBuffer &s) {
				s << allocationSize; /* AllocationSize (8 bytes) */
				s << endOfFile; /* EndOfFile (8 bytes) */
				s << numberOfLinks; /* NumberOfLinks (4 bytes) */
				s << quint8(deletePending ? 1 : 0); /* DeletePending (1 byte) */
				s << quint8(directory ? 1 : 0); /* Directory (1 byte) */
				// The 2-byte padding mentioned in MS-FSCC 2.4.38 does not seem to be used over RDP
				// s.seek(2); /* Reserved (2 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(22)) {
					return false;
				}
				quint8 boolValue;
				s >> allocationSize; /* AllocationSize (8 bytes) */
				s >> endOfFile; /* EndOfFile (8 bytes) */
				s >> numberOfLinks; /* NumberOfLinks (4 bytes) */
				s >> boolValue; /* DeletePending (1 byte) */
				deletePending = boolValue;
				s >> boolValue; /* Directory (1 byte) */
				directory = boolValue;
				// The 2-byte padding mentioned in MS-FSCC 2.4.38 does not seem to be used over RDP
				// s.seek(2); /* Reserved (2 bytes) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.8 FileBothDirectoryInformation
		 */
		class BothDirectoryInformation : public FileInformationData {
		public:
			quint32 nextEntryOffset;
			quint32 fileIndex;
			QDateTime creationTime;
			QDateTime lastAccessTime;
			QDateTime lastWriteTime;
			QDateTime changeTime;
			qint64 endOfFile;
			qint64 allocationSize;
			FileAttribute fileAttributes;
			quint32 eaSize;
			QString shortName;
			QString fileName;

			BothDirectoryInformation() {
				informationClass = FileBothDirectoryInformation;
				nextEntryOffset = 0;
				fileIndex = 0;
				QDateTime now = QDateTime::currentDateTimeUtc();
				creationTime = lastAccessTime = lastWriteTime = changeTime = now;
				endOfFile = 0;
				allocationSize = 0;
				fileAttributes = FileAttribute(0);
				eaSize = 0;
				informationClassName = "BothDirectoryInformation";
			}

			quint32 dataLength() {
				return (93 + fileName.length() * 2);
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(93)) {
					return false;
				}
				qint64  fileTime;
				quint32 attributes;
				quint32 fileNameLength;
				qint8 shortNameLength;

				s >> nextEntryOffset; /* NextEntryOffset (4 bytes) */
				/* We don't support NextEntryOffset values other than 0 */
				if (nextEntryOffset) {
					CWLOG_ERR(TAG, "error: nextEntryOffset > 0 not implemented in BothDirectoryInformation class");
					return false;
				}
				s >> fileIndex; /* FileIndex (4 bytes) */
				s >> fileTime; /* CreationTime (8 bytes) */
				FS::toQDateTime(fileTime, creationTime);
				s >> fileTime; /* LastAccessTime (8 bytes) */
				FS::toQDateTime(fileTime, lastAccessTime);
				s >> fileTime; /* LastWriteTime (8 bytes) */
				FS::toQDateTime(fileTime, lastWriteTime);
				s >> fileTime; /* ChangeTime (8 bytes) */
				FS::toQDateTime(fileTime, changeTime);
				s >> endOfFile; /* EndOfFile (8 bytes) */
				s >> allocationSize; /* AllocationSize (8 bytes) */
				s >> attributes; /* FileAttributes (4 bytes) */
				fileAttributes = FileAttribute(attributes);
				s >> fileNameLength; /* FileNameLength (4 bytes) */
				if (fileNameLength > 512 || fileNameLength % 2) {
					return false;
				}
				s >> eaSize; /* EaSize (4 bytes) */

				s >> shortNameLength; /* ShortNameLength (1 byte): An 8-bit signed integer */
				if (shortNameLength < 0 || shortNameLength > 24 || shortNameLength % 2) {
					return false;
				}
				/**
				 * Note: MS-FSCC 2.4.8 defines a 1-byte padding after the
				 * shortNameLength field but it is not used in RDP
				 */
				// s.seek(1); /* Reserved (1 byte), seems to be missing in RDP */

				if (shortNameLength) {
					shortName = QString((const QChar *)s.pointer(), shortNameLength / 2);
				}
				s.seek(24); /* ShortName (24 bytes) */

				if (fileNameLength && !s.readUnicodeString(fileName, fileNameLength)) { /* FileName (variable) */
					return false;
				}
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.11 FileDispositionInformation
		 */
		class DispositionInformation : public FileInformationData {
		public:
			bool deletePending;

			DispositionInformation() {
				informationClass = FileDispositionInformation;
				deletePending = false;
				informationClassName = "DispositionInformation";
			}

			quint32 dataLength() {
				return 4; /* correct would be 1, but see Microsoft bug below */
			}

			bool encode(RdpStreamBuffer &s) {
				s << quint8(deletePending ? 1 : 0); /* DeletePending (1 byte) */
				/**
				 * Microsoft Mac client terminates without this because it
				 * erroneously expects deletePending to be 4 bytes long
				 */
				s.seek(3);
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(1)) {
					return false;
				}
				quint8 boolValue;
				s >> boolValue;
				deletePending = boolValue; /* DeletePending (1 byte) */
				return true;
			}
		};

		/**
		 * MS-FSCC 2.4.13 FileEndOfFileInformation
		 */
		class EndOfFileInformation : public FileInformationData	{
		public:
			quint64 endOfFile;

			EndOfFileInformation(quint64 offset = 0) {
				informationClass = FileEndOfFileInformation;
				endOfFile = offset;
				informationClassName = "EndOfFileInformation";
			}

			quint32 dataLength() {
				return 8;
			}

			bool encode(RdpStreamBuffer &s) {
				s << endOfFile; /* EndOfFile (8 bytes) */
				return true;
			}

			bool decode(RdpStreamBuffer &s) {
				if (!s.verifyRemainingLength(8)) {
					return false;
				}
				s >> endOfFile; /* EndOfFile (8 bytes) */
				return true;
			}
		};
	};


	/* DEVICE REQUESTS *******************************************************/


	/**
	 * MS-RDPEFS 2.2.1.4 Device I/O Request (DR_DEVICE_IOREQUEST)
	 */
	class DeviceRequest {
	public:
		enum MajorFunction {
			IrpMjCreate						= 0x00000000,
			IrpMjClose                      = 0x00000002,
			IrpMjRead                       = 0x00000003,
			IrpMjWrite                      = 0x00000004,
			IrpMjQueryInformation           = 0x00000005,
			IrpMjSetInformation             = 0x00000006,
			IrpMjQueryVolumeInformation     = 0x0000000A,
			IrpMjSetVolumeInformation       = 0x0000000B,
			IrpMjDirectoryControl           = 0x0000000C,
			IrpMjDeviceControl              = 0x0000000E,
			IrpMjLockControl                = 0x00000011,
		};
		enum MinorFunction {
			IrpMnQueryDirectory             = 0x00000001,
			IrpMnNotifyChangeDirectory      = 0x00000002,
		};
		quint32 deviceId;
		quint32 fileId;
		quint32 completionId;
		quint32 majorId;
		quint32 minorId;
		QString requestName;

		DeviceRequest(quint32 device, quint32 file, quint32 major, quint32 minor) {
			requestName = "DR_DEVICE_IOREQUEST";
			deviceId = device;
			fileId = file;
			majorId = major;
			minorId = minor;
			completionId = 0;
		}

		virtual ~DeviceRequest() {	}

		virtual bool encode(RdpStreamBuffer &s) {
			s << quint16(RDPDR_CTYP_CORE); /* HeaderComponent (2 bytes) */
			s << quint16(PAKID_CORE_DEVICE_IOREQUEST); /* HeaderPacketId (2 bytes) */
			s << quint32(deviceId); /* DeviceId (4 bytes) */
			s << quint32(fileId); /* FileId (4 bytes) */
			s << quint32(completionId); /* CompletionId (4 bytes) */
			s << quint32(majorId); /* MajorFunction (4 bytes) */
			s << quint32(minorId); /* MinorFunction (4 bytes) */
			return true;
		}

		virtual DeviceResponse* getResponseInstance(void) = 0;
	};

	/**
	 * MS-RDPEFS 2.2.1.4.1 Device Create Request (DR_CREATE_REQ)
	 */
	class DeviceCreateRequest : public DeviceRequest {
	public:
		quint32 desiredAccess;
		quint64 allocationSize;
		quint32 fileAttributes;
		quint32 sharedAccess;
		quint32 createDisposition;
		quint32 createOptions;
		QString path;

		DeviceCreateRequest(quint32 device)
			: DeviceRequest(device, 0, IrpMjCreate, 0)
			, desiredAccess(0)
			, allocationSize(0)
			, fileAttributes(0)
			, sharedAccess(0)
			, createDisposition(0)
			, createOptions(0)
		{
			requestName = "DR_CREATE_REQ";
		}

		bool encode(RdpStreamBuffer &s) {
			DeviceRequest::encode(s); /* DeviceIoRequest (24 bytes) */
			s << quint32(desiredAccess); /* DesiredAccess (4 bytes) */
			s << quint64(allocationSize); /* AllocationSize (8 bytes) */
			s << quint32(fileAttributes); /* FileAttributes (4 bytes) */
			s << quint32(sharedAccess);/* SharedAccess (4 bytes) */
			s << quint32(createDisposition); /* CreateDisposition (4 bytes) */
			s << quint32(createOptions); /* CreateOptions (4 bytes) */

			/* Note: PathLength specifies the number of **bytes** in the Path field, including the null-terminator */
			s << quint32(path.length() * 2 + 2); /* PathLength (4 bytes) */
			s.write((const char *)path.unicode(), path.length() * 2);
			s << quint16(0); /* Path null-terminator */

			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DeviceCreateResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.4.2 Device Close Request (DR_CLOSE_REQ)
	 */
	class DeviceCloseRequest : public DeviceRequest {
	public:
		DeviceCloseRequest(quint32 device, quint32 file)
			: DeviceRequest(device, file, IrpMjClose, 0)
		{
			requestName = "DR_CLOSE_REQ";
		}

		bool encode(RdpStreamBuffer &s) {
			DeviceRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s.seek(32); /* Padding (32 bytes) */
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DeviceCloseResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.4.3 Device Read Request (DR_READ_REQ)
	 */
	class DeviceReadRequest : public DeviceRequest {
	public:
		quint32 length;
		quint64 offset;
		char *buffer;

		DeviceReadRequest(quint32 device, quint32 file, quint64 off, quint32 len, char *buf)
			: DeviceRequest(device, file, IrpMjRead, 0)
			, length(len)
			, offset(off)
			, buffer(buf)
		{
			requestName = "DR_READ_REQ";
		}

		bool encode(RdpStreamBuffer &s) {
			DeviceRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(length); /* Length (4 bytes) */
			s << quint64(offset); /* Offset (8 bytes) */
			s.seek(20); /* Padding (20 bytes) */
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DeviceReadResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.4.4 Device Write Request (DR_WRITE_REQ)
	 */
	class DeviceWriteRequest : public DeviceRequest {
	public:
		quint32 length;
		quint64 offset;
		const char *buffer;

		DeviceWriteRequest(quint32 device, quint32 file, quint64 off, quint32 len, const char *buf)
			: DeviceRequest(device, file, IrpMjWrite, 0)
			, length(len)
			, offset(off)
			, buffer(buf)
		{
			requestName = "DR_WRITE_REQ";
		}

		bool encode(RdpStreamBuffer &s) {
			DeviceRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(length); /* Length (4 bytes) */
			s << quint64(offset); /* Offset (8 bytes) */
			s.seek(20); /* Padding (20 bytes) */
			s.write(buffer, length); /* WriteData (variable) */
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DeviceWriteResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.4.5 Device Control Request (DR_CONTROL_REQ)
	 */
	class DeviceControlRequest : public DeviceRequest {
	public:
		enum ControlCode {
			/* See MS-FSCC 2.3 */
			FsctlCreateOrGetObjectId            = 0x000900c0,
			FsctlDeleteObjectId                 = 0x000900a0,
			FsctlDeleteReparsePoint             = 0x000900ac,
			FsctlFileLevelTrim                  = 0x00098208,
			FsctlFilesystemGetStatistics        = 0x00090060,
			FsctlFindFilesBySid                 = 0x0009008f,
			FsctlGetCompression                 = 0x0009003c,
			FsctlGetIntegrityInformation        = 0x0009027c,
			FsctlGetNtfsVolumeData              = 0x00090064,
			FsctlGetRefsVolumeData              = 0x000902D8,
			FsctlGetOnjectId                    = 0x0009009c,
			FsctlGetReparsePoint                = 0x000900a8,
			FsctlGetRetrievalPointers           = 0x00090073,
			FsctlIS_PathnameValid               = 0x0009002c,
			FsctlLmrSetLinkTrackingInformation  = 0x001400ec,
			FsctlOffloadRead                    = 0x00094264,
			FsctlOffloadWrite                   = 0x00098268,
			FsctlPipePeek                       = 0x0011400c,
			FsctlPipeTranseive                  = 0x0011c017,
			FsctlPipeWait                       = 0x00110018,
			FsctlQueryAllocatedRanges           = 0x000940cf,
			FsctlQueryFatBpb                    = 0x00090058,
			FsctlQueryFileRegion                = 0x00090284,
			FsctlQueryOnDiskVolumeInfo          = 0x0009013c,
			FsctlQuerySparsingInfo              = 0x00090138,
			FsctlReadFileUsnData                = 0x000900eb,
			FsctlRecallFile                     = 0x00090117,
			FsctlSetCompression                 = 0x0009c040,
			FsctlSetDefectManagement            = 0x00098134,
			FsctlSetEncryption                  = 0x000900D7,
			FsctlSetIntegrityInformation        = 0x0009C280,
			FsctlSetObjectId                    = 0x00090098,
			FsctlSetObjectIdExtended            = 0x000900bc,
			FsctlSetReparsePoint                = 0x000900a4,
			FsctlSetSparse                      = 0x000900c4,
			FsctlSetZeroData                    = 0x000980c8,
			FsctlSetZeroOnDeallocation          = 0x00090194,
			FsctlSisCopyfile                    = 0x00090100,
			FsctlWriteUsnCloseRecord            = 0x000900ef,
		};

		quint32 outputBufferLength;
		quint32 ioControlCode;
		QByteArray buffer;

		DeviceControlRequest(quint32 device)
			: DeviceRequest(device, 0, IrpMjDeviceControl, 0)
			, outputBufferLength(0)
			, ioControlCode(0)
		{
			requestName = "DR_CONTROL_REQ";
		}

		bool encode(RdpStreamBuffer &s) {
			DeviceRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(outputBufferLength); /* OutputBufferLength (4 bytes) */
			s << quint32(buffer.size()); /* InputBufferLength (4 bytes) */
			s << quint32(ioControlCode); /* IoControlCode (4 bytes) */
			s.seek(20); /* Padding (20 bytes) */
			s << buffer; /* InputBuffer (variable) */
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DeviceControlResponse(*this);
		}
	};


	/* SERVER DRIVE REQUESTS *************************************************/


	/**
	 * MS-RDPEFS 2.2.3.3 Server Drive I/O Request (DR_DRIVE_CORE_DEVICE_IOREQUEST)
	 */
	typedef DeviceRequest DriveRequest;

	/**
	 * MS-RDPEFS 2.2.3.3.1 Server Create Drive Request (DR_DRIVE_CREATE_REQ)
	 */
	typedef DeviceCreateRequest DriveCreateRequest;

	/**
	 * MS-RDPEFS 2.2.3.3.2 Server Close Drive Request (DR_DRIVE_CLOSE_REQ)
	 */
	typedef DeviceCloseRequest DriveCloseRequest;

	/**
	 * MS-RDPEFS 2.2.3.3.3 Server Drive Read Request (DR_DRIVE_READ_REQ)
	 */
	typedef DeviceReadRequest DriveReadRequest;

	/**
	 * MS-RDPEFS 2.2.3.3.4 Server Drive Write Request (DR_DRIVE_WRITE_REQ)
	 */
	typedef DeviceWriteRequest DriveWriteRequest;

	/**
	 * MS-RDPEFS 2.2.3.3.5 Server Drive Control Request (DR_DRIVE_CONTROL_REQ)
	 */
	typedef DeviceControlRequest DriveControlRequest;


	/**
	 * MS-RDPEFS 2.2.3.3.6 Server Drive Query Volume Information Request (DR_DRIVE_QUERY_VOLUME_INFORMATION_REQ)
	 */
	class DriveQueryVolumeInformationRequest : public DriveRequest {
	public:
		FS::VolumeInformationData *volumeInformationData;

		DriveQueryVolumeInformationRequest(quint32 device, FS::VolumeInformationData &informationData)
			: DriveRequest(device, 0, IrpMjQueryVolumeInformation, 0)
			, volumeInformationData(NULL)
		{
			requestName = "DR_DRIVE_QUERY_VOLUME_INFORMATION_REQ";

			switch (informationData.informationClass) {
				case FS::FileFsVolumeInformation:
				case FS::FileFsSizeInformation:
				case FS::FileFsDeviceInformation:
				case FS::FileFsAttributeInformation:
				case FS::FileFsFullSizeInformation:
					volumeInformationData = &informationData;
					break;
				default:
					CWLOG_ERR(TAG, "error: invalid information class for DriveQueryVolumeInformationRequest: %u",
						 informationData.informationClass);
			}
		}

		bool encode(RdpStreamBuffer &s) {
			if (!volumeInformationData) {
				return false;
			}
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(volumeInformationData->informationClass); /* FsInformationClass (4 bytes) */
			s << quint32(volumeInformationData->dataLength()); /* Length (4 bytes) */
			s.seek(24); /* Padding (24 bytes) */
			return volumeInformationData->encode(s); /* QueryVolumeBuffer (variable) */
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveQueryVolumeInformationResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.7 Server Drive Set Volume Information Request (DR_DRIVE_SET_VOLUME_INFORMATION_REQ)
	 */
	class DriveSetVolumeInformationRequest : public DriveRequest {
	public:
		FS::VolumeInformationData *volumeInformationData;

		DriveSetVolumeInformationRequest(quint32 device, FS::VolumeInformationData &informationData)
			: DriveRequest(device, 0, IrpMjSetVolumeInformation, 0)
			, volumeInformationData(NULL)
		{
			requestName = "DR_DRIVE_SET_VOLUME_INFORMATION_REQ";

			switch (informationData.informationClass) {
				case FS::FileFsLabelInformation:
					volumeInformationData =  &informationData;
					break;
				default:
					CWLOG_ERR(TAG, "error: invalid information class for DriveSetVolumeInformationRequest: %u",
						informationData.informationClass);
			}
		}

		bool encode(RdpStreamBuffer &s) {
			if (!volumeInformationData) {
				return false;
			}
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(volumeInformationData->informationClass); /* FsInformationClass (4 bytes) */
			s << quint32(volumeInformationData->dataLength()); /* Length (4 bytes) */
			s.seek(24); /* Padding (24 bytes) */
			return volumeInformationData->encode(s); /* QueryVolumeBuffer (variable) */
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveSetVolumeInformationResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.8 Server Drive Query Information Request (DR_DRIVE_QUERY_INFORMATION_REQ)
	 */
	class DriveQueryInformationRequest : public DriveRequest {
	public:
		FS::FileInformationData *fileInformationData;

		DriveQueryInformationRequest(quint32 device, quint32 file, FS::FileInformationData &informationData)
			: DriveRequest(device, file, IrpMjQueryInformation, 0)
			, fileInformationData(NULL)
		{
			requestName = "DR_DRIVE_QUERY_INFORMATION_REQ";

			switch (informationData.informationClass) {
				case FS::FileBasicInformation:
				case FS::FileStandardInformation:
				case FS::FileAttributeTagInformation:
					fileInformationData = &informationData;
					break;
				default:
					CWLOG_ERR(TAG, "error: invalid information class for DriveQueryInformationRequest: %u",
						informationData.informationClass);
			}
		}

		bool encode(RdpStreamBuffer &s) {
			if (!fileInformationData) {
				return false;
			}
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			CWLOG_DBG(TAG, "information class: %s", QCSTR(fileInformationData->informationClassName));
			s << quint32(fileInformationData->informationClass); /* FsInformationClass (4 bytes) */
#if 1
			/* No need to add the fileInformation buffers in this request */
			s << quint32(0); /* Length (4 bytes) */
			s.seek(24); /* Padding (24 bytes) */
			return true;
#else
			s << quint32(fileInformationData->dataLength()); /* Length (4 bytes) */
			s.seek(24); /* Padding (24 bytes) */
			return fileInformationData->encode(s); /* QueryBuffer (variable) */
#endif
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveQueryInformationResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.9 Server Drive Set Information Request (DR_DRIVE_SET_INFORMATION_REQ)
	 */
	class DriveSetInformationRequest : public DriveRequest {
	public:
		FS::FileInformationData *fileInformationData;

		DriveSetInformationRequest(quint32 device, quint32 file, FS::FileInformationData &informationData)
			: DriveRequest(device, file, IrpMjSetInformation, 0)
			, fileInformationData(NULL)
		{
			requestName = "DR_DRIVE_SET_INFORMATION_REQ";

			switch (informationData.informationClass) {
				case FS::FileBasicInformation:
				case FS::FileRenameInformation:
				case FS::FileDispositionInformation:
				case FS::FileAllocationInformation:
				case FS::FileEndOfFileInformation:
					fileInformationData = &informationData;
					break;
				default:
					CWLOG_ERR(TAG, "error: invalid information class for DriveSetInformationRequest: %u",
						informationData.informationClass);
			}
		}

		bool encode(RdpStreamBuffer &s) {
			if (!fileInformationData) {
				return false;
			}
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			CWLOG_DBG(TAG, "information class: %s", QCSTR(fileInformationData->informationClassName));
			s << quint32(fileInformationData->informationClass); /* FsInformationClass (4 bytes) */
			s << quint32(fileInformationData->dataLength()); /* Length (4 bytes) */
			s.seek(24); /* Padding (24 bytes) */
			if (fileInformationData->encode(s)) { /* SetBuffer (variable) */
				quint32 len = fileInformationData->dataLength();
				return true;
			}
			return false;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveSetInformationResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.10 Server Drive Query Directory Request (DR_DRIVE_QUERY_DIRECTORY_REQ)
	 */
	class DriveQueryDirectoryRequest : public DriveRequest {
	public:
		FS::FileInformationData *fileInformationData;
		QString pathName;

		DriveQueryDirectoryRequest(quint32 device, quint32 file, const QString &path, FS::FileInformationData &informationData)
			: DriveRequest(device, file, IrpMjDirectoryControl, IrpMnQueryDirectory)
			, fileInformationData(NULL)
			, pathName(path)
		{
			requestName = "DR_DRIVE_QUERY_DIRECTORY_REQ";

			switch (informationData.informationClass) {
				/* Not required/implemented case FS::FileDirectoryInformation: */
				/* Not required/implemented case FS::FileFullDirectoryInformation: */
				case FS::FileBothDirectoryInformation:
				case FS::FileNamesInformation:
					fileInformationData = &informationData;
					break;
				default:
					CWLOG_ERR(TAG, "error: invalid information class for DriveQueryDirectoryRequest: %u",
						informationData.informationClass);
			}
		}

		bool encode(RdpStreamBuffer &s) {
			if (!fileInformationData) {
				return false;
			}
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			CWLOG_DBG(TAG, "information class: %s", QCSTR(fileInformationData->informationClassName));
			s << quint32(fileInformationData->informationClass); /* FsInformationClass (4 bytes) */
			s << quint8(pathName.isEmpty() ? 0 : 1); /* InitialQuery (1 byte) */
			if (pathName.isEmpty()) {
				s << quint32(0);
			} else {
				s << quint32(pathName.length() * 2 + 2); /* PathLength (4 bytes) including the null-terminator */
			}
			s.seek(23); /* Padding (23 bytes) */
			if (!pathName.isEmpty()) {
				s.writeUnicodeString(pathName, true); /* Path (variable), null-terminated */
			}
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveQueryDirectoryResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.11 Server Drive NotifyChange Directory Request (DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_REQ)
	 */
	class DriveNotifyChangeDirectoryRequest : public DriveRequest {
	public:
		enum CompletionFilter {
			/* See MS-SMB2 2.2.35 */
			FileNotifyChangeFileName    = 0x00000001,
			FileNotifyChangeDirName     = 0x00000002,
			FileNotifyChangeAttributes  = 0x00000004,
			FileNotifyChangeSize        = 0x00000008,
			FileNotifyChangeLastWrite   = 0x00000010,
			FileNotifyChangeLastAccess  = 0x00000020,
			FileNotifyChangeCreation    = 0x00000040,
			FileNotifyChangeEa          = 0x00000080,
			FileNotifyChangeSecurity    = 0x00000100,
			FileNotifyChangeStreamName  = 0x00000200,
			FileNotifyChangeStreamSize  = 0x00000400,
			FileNotifyChangeStreamWrite = 0x00000800,
		};

		bool watchTree;
		quint32 completionFilter;

		DriveNotifyChangeDirectoryRequest(quint32 device)
			: DriveRequest(device, 0, IrpMjDirectoryControl, IrpMnNotifyChangeDirectory)
			, watchTree(false)
			, completionFilter(0)
		{
			requestName = "DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_REQ";
			CWLOG_ERR(TAG, "error: DriveNotifyChangeDirectoryRequest is not implemented");
		}

		bool encode(RdpStreamBuffer &s) {
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint8(watchTree); /* InitialQuery (1 byte) */
			s << quint32(completionFilter); /* CompletionFilter (4 bytes) */
			s.seek(27); /* Padding (27 bytes) */
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveNotifyChangeDirectoryResponse(*this);
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.3.12 Server Drive Lock Control Request (DR_DRIVE_LOCK_REQ)
	 */
	class DriveLockControlRequest : public DriveRequest {
	public:
		enum Operation {
			RdpLowioOpSharedlock        = 0x00000002,
			RdpLowioOpExclusivelock     = 0x00000003,
			RdpLowioOpUnlock            = 0x00000004,
			RdpLowioOpUnlockMultiple    = 0x00000005,
		};

		struct LockInfo {
			quint64 length;
			quint64 offset;
		};

		quint32 operation;
		bool waitLockComplete;
		QList <LockInfo> locks;

		DriveLockControlRequest(quint32 device, quint32 file)
			: DriveRequest(device, file, IrpMjLockControl, 0)
			, operation(0)
			, waitLockComplete(false)
		{
			requestName = "DR_DRIVE_LOCK_REQ";
			CWLOG_ERR(TAG, "error: DriveLockControlRequest is not implemented");
		}

		bool encode(RdpStreamBuffer &s) {
			DriveRequest::encode(s);  /* DeviceIoRequest (24 bytes) */
			s << quint32(operation); /* Operation (4 bytes) */
			s << quint32(waitLockComplete ? 0xFFFFFFFF : 0); /* F(1 bit) and Padding (31 bits) */
			s << quint32(locks.size()); /* NumLocks (4 bytes) */
			s.seek(20); /* Padding2 (20 bytes) */
			foreach(const LockInfo &l, locks) {
				s << quint64(l.length);
				s << quint64(l.offset);
			}
			return true;
		}

		DeviceResponse* getResponseInstance(void) {
			return new DriveLockControlResponse(*this);
		}
	};


	/* DEVICE RESPONSES ******************************************************/


	/**
	 * MS-RDPEFS 2.2.1.5 Device I/O Response (DR_DEVICE_IOCOMPLETION)
	 */
	class DeviceResponse {
	private:
		QMutex completionMutex;
		QWaitCondition completionCondition;

	public:
		bool waitForCompletion(unsigned long time = ULONG_MAX)  {
			QMutexLocker lock(&completionMutex);
			bool rv = completionCondition.wait(&completionMutex, time);
			return rv;
		}
		void signalCompletion(bool responseArrived) {
			QMutexLocker lock(&completionMutex);
			arrived = responseArrived;
			completionCondition.wakeAll();
		}
		quint32 deviceId;
		quint32 completionId;
		quint32 ioStatus;
		quint32 bufferLength;
		QString responseName;
		bool arrived;

		DeviceResponse(const DeviceRequest &dev) {
			responseName = "DR_DEVICE_IOCOMPLETION";
			deviceId = dev.deviceId;
			completionId = dev.completionId;
			ioStatus = 0;
			bufferLength = 0;
			arrived = false;
		}

		virtual ~DeviceResponse() {	}

		virtual bool decode(RdpStreamBuffer &s) = 0;

		bool decodeBufferLength(RdpStreamBuffer &s, bool verifyStreamLength = true) {
			if (!s.verifyRemainingLength(4)) {
				return false;
			}
			s >> bufferLength; /* Length (4 bytes) */

			if (verifyStreamLength && !s.verifyRemainingLength(bufferLength)) {
				return false;
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.5.1 Device Create Response (DR_CREATE_RSP)
	 */
	class DeviceCreateResponse : public DeviceResponse {
	public:
		quint32 fileId;
		quint8  information;

		DeviceCreateResponse(const DeviceCreateRequest &dev) : DeviceResponse(dev) {
			responseName = "DR_CREATE_RSP";
			fileId = 0;
			information = 0;
		}

		bool decode(RdpStreamBuffer &s) {
			if (!s.verifyRemainingLength(4)) {
				return false;
			}
			s >> fileId; /* FileId (4 bytes) */

			/**
			 * Note: If the IoStatus field is set to 0x00000000, the
			 *       Information field MAY be skipped.
			 *       All Windows versions skip the Information field if IoStatus
			 *       is set to 0x00000000 and DeviceId has DeviceType set
			 *       to RDPDR_DTYP_PRINT.
			 */

			if (!s.verifyRemainingLength(1)) {
				if (ioStatus == 0x00000000) {
					information = 0x00;
				} else {
					return false;
				}
			} else {
				s >> information; /* Information (1 byte) */
			}

			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.5.2 Device Close Response (DR_CLOSE_RSP)
	 */
	class DeviceCloseResponse : public DeviceResponse {
	public:
		DeviceCloseResponse(const DeviceCloseRequest &dev) : DeviceResponse(dev) {
			responseName = "DR_CLOSE_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			/* Note:
			 * MS-RDPEFS 2.2.1.5.2 defines a 5-byte padding
			 * mstsc does only adds a 4-byte padding
			 * freerdp correctly adds a 5-byte padding
			 * ... better skip the remaining padding length verification completely
			 */
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.5.3 Device Read Response (DR_READ_RSP)
	 */
	class DeviceReadResponse : public DeviceResponse {
	public:
		char *buffer;
		quint32 maxLength;

		DeviceReadResponse(const DeviceReadRequest &dev)
			: DeviceResponse(dev)
			, buffer(dev.buffer)
			, maxLength(dev.length)
		{
			responseName = "DR_READ_RSP";
		}

		~DeviceReadResponse() {
			//free(buffer);
		}

		bool decode(RdpStreamBuffer &s) {
			if (!s.verifyRemainingLength(4)) {
				return false;
			}
			s >> bufferLength; /* Length (4 bytes) */

			if (bufferLength > maxLength) {
				CWLOG_ERR(TAG, "error: invalid buffer length in device read response: %u", bufferLength);
				return false;
			}

			if (bufferLength) {
				if (!s.verifyRemainingLength(bufferLength)) {
					return false;
				}
				//buffer = malloc(bufferLength);
				if (buffer) {
					memcpy(buffer, s.pointer(), bufferLength);
					s.seek(bufferLength);  /* ReadData (variable) */
				}
			}

			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.5.4 Device Write Response (DR_WRITE_RSP)
	 */
	class DeviceWriteResponse : public DeviceResponse {
	public:
		quint32 maxLength;

		DeviceWriteResponse(const DeviceWriteRequest &dev)
			: DeviceResponse(dev)
			, maxLength(dev.length)
		{
			responseName = "DR_WRITE_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!s.verifyRemainingLength(4)) {
				return false;
			}
			s >> bufferLength; /* Length (4 bytes) */
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.1.5.5 Device Control Response (DR_CONTROL_RSP)
	 */
	class DeviceControlResponse : public DeviceResponse {
	public:
		QByteArray buffer;

		DeviceControlResponse(const DeviceControlRequest &dev) : DeviceResponse(dev) {
			responseName = "DR_CONTROL_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!s.verifyRemainingLength(4)) {
				return false;
			}
			s >> bufferLength; /* OutputBufferLength (4 bytes) */

			if (bufferLength)	{
				if (!s.verifyRemainingLength(bufferLength)) {
					return false;
				}
				buffer = QByteArray(s.pointer(), bufferLength);
				s.seek(bufferLength);  /* ReadData (variable) */
			} else {
				/**
				 * Note: According to MS-RDPEFS the OutputBuffer minimum size
				 * is 1 byte; that is, if OutputBufferLength is 0, this field
				 * MUST have 1 byte of extra padding.
				 * However: mstsc and other clients do not adhere to this in all
				 * situations. E.g. if sending an invalid DeviceControlRequest
				 * one will receive a DeviceControlResponse with
				 * outputBufferLength=0 but without 1-byte outputBuffer
				 */
			}
			return true;
		}
	};


	/* CLIENT DRIVE RESPONSES ************************************************/


	/**
	 * MS-RDPEFS 2.2.3.4 Client Drive I/O Response (DR_DRIVE_CORE_DEVICE_IOCOMPLETION)
	 */
	typedef DeviceResponse DriveResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.1 Client Drive Create Response (DR_DRIVE_CREATE_RSP)
	 */
	typedef DeviceCreateResponse DriveCreateResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.2 Client Drive Close Response (DR_DRIVE_CLOSE_RSP)
	 */
	typedef DeviceCloseResponse DriveCloseResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.3 Client Drive Read Response (DR_DRIVE_READ_RSP)
	 */
	typedef DeviceReadResponse DriveReadResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.4 Client Drive Write Response (DR_DRIVE_WRITE_RSP)
	 */
	typedef DeviceWriteResponse DriveWriteResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.5 Client Drive Control Response (DR_DRIVE_CONTROL_RSP)
	 */
	typedef DeviceControlResponse DriveControlResponse;

	/**
	 * MS-RDPEFS 2.2.3.4.6 Client Drive Query Volume Information Response (DR_DRIVE_QUERY_VOLUME_INFORMATION_RSP)
	 */
	class DriveQueryVolumeInformationResponse : public DriveResponse {
	public:
		FS::VolumeInformationData *volumeInformationData;

		DriveQueryVolumeInformationResponse(const DriveQueryVolumeInformationRequest &dev)
			: DeviceResponse(dev)
			, volumeInformationData(dev.volumeInformationData)
		{
			responseName = "DR_DRIVE_QUERY_VOLUME_INFORMATION_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!volumeInformationData) {
				return false;
			}
			if (!decodeBufferLength(s)) {
				return false;
			}
			if (bufferLength && !volumeInformationData->decode(s)) {
				return false;
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.7 Client Drive Set Volume Information Response (DR_DRIVE_SET_VOLUME_INFORMATION_RSP)
	 */
	class DriveSetVolumeInformationResponse : public DriveResponse {
	public:
		quint32 expectedLength;

		DriveSetVolumeInformationResponse(const DriveSetVolumeInformationRequest &dev)
			: DeviceResponse(dev)
			, expectedLength(dev.volumeInformationData->dataLength())
		{
			responseName = "DR_DRIVE_SET_VOLUME_INFORMATION_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!decodeBufferLength(s, false)) {
				return false;
			}
			/* Length MUST match the Length field in the Server Drive Set Volume
			 * Information Request. */
			if (bufferLength != expectedLength) {
				return false;
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.8 Client Drive Query Information Response (DR_DRIVE_QUERY_INFORMATION_RSP)
	 */
	class DriveQueryInformationResponse : public DriveResponse {
	public:
		FS::FileInformationData *fileInformationData;

		DriveQueryInformationResponse(DriveQueryInformationRequest &dev)
			: DeviceResponse(dev)
			, fileInformationData(dev.fileInformationData)
		{
			responseName = "DR_DRIVE_QUERY_INFORMATION_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!fileInformationData) {
				return false;
			}
			if (!decodeBufferLength(s)) {
				return false;
			}
			if (bufferLength && !fileInformationData->decode(s)) {
				return false;
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.9 Client Drive Set Information Response (DR_DRIVE_SET_INFORMATION_RSP)
	 */
	class DriveSetInformationResponse : public DriveResponse {
	public:
		quint32 expectedLength;

		DriveSetInformationResponse(const DriveSetInformationRequest &dev)
			: DeviceResponse(dev)
			, expectedLength(dev.fileInformationData->dataLength())
		{
			responseName = "DR_DRIVE_SET_INFORMATION_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!decodeBufferLength(s, false)) {
				return false;
			}
			/* Length field MUST be equal to the Length field in the Server Drive
			 * Set Information Request (section 2.2.3.3.9).
			 */
			if (bufferLength != expectedLength) {
				if (bufferLength == 0) {
					/**
					 * rdesktop erroneously always sends a zero length value.
					 * For now we accept this protocol error.
					 **/
					return true;
				}
				CWLOG_ERR(TAG, "error: client passed an invalid length in DriveSetInformationResponse");
				return false;
			}

			/**
			 * The Microsoft Mac client (8.0.8 build 25010) erroneously and
			 * unnecessarily adds the complete request buffer in the response.
			 * Don't do a remaining length verification here.
			 */
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.10 Client Drive Query Directory Response (DR_DRIVE_QUERY_DIRECTORY_RSP)
	 */
	class DriveQueryDirectoryResponse : public DriveResponse {
	public:
		FS::FileInformationData *fileInformationData;

		DriveQueryDirectoryResponse(const DriveQueryDirectoryRequest &dev)
			: DeviceResponse(dev)
			, fileInformationData(dev.fileInformationData)
		{
			responseName = "DR_DRIVE_QUERY_DIRECTORY_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!fileInformationData) {
				return false;
			}
			if (!decodeBufferLength(s)) {
				return false;
			}
			if (bufferLength && !fileInformationData->decode(s)) {
				return false;
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.11 Client Drive NotifyChange Directory Response (DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_RSP)
	 */
	class DriveNotifyChangeDirectoryResponse : public DriveResponse {
	public:
		DriveNotifyChangeDirectoryResponse(const DriveNotifyChangeDirectoryRequest &dev) : DeviceResponse(dev) {
			responseName = "DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			if (!decodeBufferLength(s)) {
				return false;
			}
			if (bufferLength) {
				/*
				 * This field is an array of FILE_NOTIFY_INFORMATION structures,
				 * as specified in [MS-FSCC] section 2.4.42.
				 */
				CWLOG_ERR(TAG, "error: DriveNotifyChangeDirectoryResponse is not implemented");
				s.seek(bufferLength);  /* Buffer (variable) */
			}
			return true;
		}
	};

	/**
	 * MS-RDPEFS 2.2.3.4.12 Client Drive Lock Control Response (DR_DRIVE_LOCK_RSP)
	 */
	class DriveLockControlResponse : public DriveResponse {
	public:
		DriveLockControlResponse(const DriveLockControlRequest &dev) : DeviceResponse(dev) {
			responseName = "DR_DRIVE_LOCK_RSP";
		}

		bool decode(RdpStreamBuffer &s) {
			/* Padding (5 bytes) */
			return true;
		}
	};


	/* FUSE DRIVE BACKEND ****************************************************/

public:
	class FuseThread : public QThread {
	private:
		uid_t userId;
		gid_t groupId;

		RdpDrDevice *mDevice;
		QDir mMountPoint;
		fuse* mFuseHandle;
		fuse_chan *mFuseCommHandle;
		RDPDrChannelServer *mVirtualChannel;
		QMutex mFuseLoopLock;
		QMutex mIoLock;

#ifdef USE_STAT_CACHE
		class StatCache {
		public:
			void add(const QString &key, const struct stat *val) {
				CacheItem &item = cache[key];
				item.stbuf = *val;
				item.time.start();
			}
			bool get(const QString &key, struct stat *val) {
				StatCachesIterator it = cache.find(key);
				if (it == cache.end()) {
					return false;
				}
				if (it.value().time.elapsed() > 5000) {
					cache.erase(it);
					return false;
				}
				*val = it.value().stbuf;
				return true;
			}
		private:
			struct CacheItem {
				struct stat stbuf;
				QTime time;
			};
			typedef QMap<QString, CacheItem> StatCaches;
			typedef StatCaches::iterator StatCachesIterator;
			StatCaches cache;
		};

		StatCache mStatCache;
#endif /* USE_STAT_CACHE */

		int convertNtStatus(quint32 ntstatus);
		QString toWindowsSeparators(const QString &path);

		quint32 createHandle(const QString &path, const FS::DesiredAccess &desiredAccess, const FS::CreateOptions &createOptions, const FS::CreateDisposition &createDisposition, const FS::FileAttribute &attributes, quint32 &fileId);
		quint32 closeHandle(quint32 &fileId);
		quint32 setFileInformationData(quint32 fileId, FS::FileInformationData &data);
		quint32 getFileInformationData(quint32 fileId, FS::FileInformationData &data);
		quint32 getDirectoryInformationData(quint32 fileId, const QString &path, FS::FileInformationData &data);
		quint32 getVolumeInformationData(FS::VolumeInformationData &data);

		void run();

	public:
		FuseThread(RDPDrChannelServer *pChannel, RdpDrDevice *device, const QString &mountDir);
		~FuseThread();

		bool unmount();

		quint32 fuseCommonGetAttr(quint32 fileId, struct stat *stbuf);
		quint32 fuseCommonTruncate(quint32 fileId, off_t offset);

		int fuseOpen(const char *path, struct fuse_file_info *fi);
		int fuseRelease(const char *path, struct fuse_file_info *fi);
		int fuseGetAttr(const char *path, struct stat *stbuf);
		int fuseFGetAttr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
		int fuseReleaseDir(const char *path, struct fuse_file_info *fi);
		int fuseOpenDir(const char *path, struct fuse_file_info *fi);
		int fuseReadDir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
		int fuseRead(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
		int fuseWrite(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
		int fuseUnlink(const char *path);
		int fuseMkDir(const char *path, mode_t mode);
		int fuseRmDir(const char *path);
		int fuseTruncate(const char *path, off_t offset);
		int fuseFTruncate(const char *path, off_t offset, struct fuse_file_info *fi);
		int fuseCreate(const char *path, mode_t mode, struct fuse_file_info *fi);
		int fuseUtimens(const char *path, const struct timespec times[2]);
		int fuseRename(const char *path, const char *newPath);
		int fuseStatfs(const char *path, struct statvfs *stvfs);

		static int fuse_open(const char *path, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseOpen(path, fi);
		}
		static int fuse_release(const char *path, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseRelease(path, fi);
		}
		static int fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseFGetAttr(path, stbuf, fi);
		}
		static int fuse_getattr(const char *path, struct stat *stbuf) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseGetAttr(path, stbuf);
		}
		static int fuse_releasedir(const char *path, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseReleaseDir(path, fi);
		}
		static int fuse_opendir(const char *path, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseOpenDir(path, fi);
		}
		static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseReadDir(path, buf, filler, offset, fi);
		}
		static int fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseRead(path, buf, size, offset, fi);
		}
		static int fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseWrite(path, buf, size, offset, fi);
		}
		static int fuse_unlink(const char *path) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseUnlink(path);
		}
		static int fuse_mkdir(const char *path, mode_t mode) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseMkDir(path, mode);
		}
		static int fuse_rmdir(const char *path) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseRmDir(path);
		}
		static int fuse_truncate(const char *path, off_t offset) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseTruncate(path, offset);
		}
		static int fuse_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseFTruncate(path, offset, fi);
		}
		static int fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseCreate(path, mode, fi);
		}
		static int fuse_utimens(const char *path, const struct timespec tv[2]) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseUtimens(path, tv);
		}
		static int fuse_rename(const char *path, const char *newPath) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseRename(path, newPath);
		}
		static int fuse_statfs(const char *path, struct statvfs *stvfs) {
			return ((FuseThread*)fuse_get_context()->private_data)->fuseStatfs(path, stvfs);
		}
	};

	bool mountDevice(RdpDrDevice *device);

private slots:
	void deviceContextStopped();
	void handleUnixSignal(int signum);

};

#endif /* RDPDRCHANNELSERVER_H */
