/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * X11 Clipboard Redirection Server Qt Class
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
#include <QTime>
#include <QThread>

#include "rdpx11clipchannelserver.h"

#include <ogon-channels/logging.h>
#define TAG CWLOG_TAG("rdpclipsrvx11")


RdpX11ClipChannelServer::RdpX11ClipChannelServer(
	QApplication *app, bool useDelayedRendering, bool usePrimarySelection, QObject *parent)
	: RDPClipChannelServer(app, useDelayedRendering, usePrimarySelection, true, parent)
{
	connect(unixSignalHandler, SIGNAL(activated(int)), this, SLOT(handleUnixSignal(int)));
	unixSignalHandler->watch(SIGHUP);
	unixSignalHandler->watch(SIGINT);
	unixSignalHandler->watch(SIGTERM);

	if (!useDelayedRendering) {
		CWLOG_WRN(TAG, "warning: delayed rendering is disabled");
		return;
	}
	if (!(mXcbConnection = xcb_connect (NULL, NULL))) {
		CWLOG_ERR(TAG, "error creating xcb connection");
		return;
	}

	if (XCB_ATOM_NONE == (mXcbClipboardManagerAtom = atomFromString("CLIPBOARD_MANAGER", false))) {
		CWLOG_ERR(TAG, "error getting clipboard manager atom");
		return;
	}
	if (XCB_ATOM_NONE == (mXcbClipboardAtom = atomFromString("CLIPBOARD", false))) {
		CWLOG_ERR(TAG, "error getting clipboard selection atom");
		return;
	}
	if (XCB_ATOM_NONE == (mXcbPrimaryAtom = atomFromString("PRIMARY", false))) {
		CWLOG_ERR(TAG, "error getting primary selection atom");
		return;
	}
	if (XCB_ATOM_NONE == (mXcbUtf8TargetAtom = atomFromString("UTF8_STRING", false))) {
		CWLOG_ERR(TAG, "error getting utf8 target atom");
		return;
	}
	if (XCB_ATOM_NONE == (mXcbHtmlTargetAtom = atomFromString("text/html", false))) {
		CWLOG_ERR(TAG, "error getting html target atom");
		return;
	}
	app->installNativeEventFilter(this);
}

RdpX11ClipChannelServer::~RdpX11ClipChannelServer() {
	unixSignalHandler->destroy();
}

void RdpX11ClipChannelServer::handleUnixSignal(int signum) {
	switch(signum) {
		case SIGHUP:
			CWLOG_DBG(TAG, "SIGHUP received. terminating ...");
			break;
		case SIGINT:
			CWLOG_DBG(TAG, "SIGINT received. terminating ...");
			break;
		case SIGTERM:
			CWLOG_DBG(TAG, "SIGTERM received. terminating ...");
			break;
		default:
			CWLOG_DBG(TAG, "WARNING: ignoring unexpected unix signal %d", signum);
	}
	qApp->exit(0);
}

bool RdpX11ClipChannelServer::nativeEventFilter(const QByteArray &eventType,
			void *message, long *)
{
	//CWLOG_DBG(TAG, "entering %s with eventType [%s]", __FUNCTION__, eventType.constData());

	if (eventType != "xcb_generic_event_t") {
		return false;
	}

	if (!isStarted()) {
		return false;
	}

	if (isWaitingForFormatDataResponse()) {
		return false;
	}

	xcb_generic_event_t* ge = static_cast<xcb_generic_event_t *>(message);
	uint responseType = ge->response_type & ~0x80;
	if (responseType != XCB_SELECTION_REQUEST) {
		return false;
	}

	xcb_selection_request_event_t *e = (xcb_selection_request_event_t *)ge;

#if 0
	CWLOG_DBG(TAG, "xcb event: SELECTION_REQUEST:");
	CWLOG_DBG(TAG, "           owner:     0x%08X", e->owner);
	CWLOG_DBG(TAG, "           requestor: 0x%08X", e->requestor);
	CWLOG_DBG(TAG, "           selection: %s", QCSTR(stringFromAtom(e->selection)));
	CWLOG_DBG(TAG, "           target:    %s", QCSTR(stringFromAtom(e->target)));
	CWLOG_DBG(TAG, "           property:  %s", QCSTR(stringFromAtom(e->property)));
#endif

	if (e->selection == mXcbClipboardAtom) {
		if (!isClipboardOwner()) {
			return false;
		}
	} else if (e->selection == mXcbPrimaryAtom) {
		if (!isSelectionOwner()) {
			return false;
		}
	} else {
		return false;
	}

	xcb_window_t clipMgmtOwner = getSelectionOwner(mXcbClipboardManagerAtom);

	if (clipMgmtOwner != e->owner) {
		if (clipMgmtOwner != XCB_WINDOW_NONE) {
			CWLOG_DBG(TAG, "current clipboard manager is window 0x%08X", clipMgmtOwner);
		}
		CWLOG_DBG(TAG, "taking over clipboard manager control");
		setSelectionOwner(mXcbClipboardManagerAtom, e->owner);
		// FIXME: undo this before quit (set owner to XCB_WINDOW_NONE)
	}

	if (e->target == mXcbUtf8TargetAtom) {
		sendTextFormatRequest();
	} else if (e->target == mXcbHtmlTargetAtom) {
		sendHtmlFormatRequest();
	}

	if (isWaitingForFormatDataResponse()) {
		/* block up to 30 seconds for the data to arrive */
		QTime t;
		t.start();
		while (t.elapsed() < 30000 && isWaitingForFormatDataResponse() && isStarted()) {
			QCoreApplication::processEvents();
			QThread::msleep(5);
		}

		if (isWaitingForFormatDataResponse()) {
			CWLOG_WRN(TAG, "warning: no data response received within %llu ms", t.elapsed());
			return false;
		}

		CWLOG_DBG(TAG, "received response after %llu ms", t.elapsed());
	}

	return false;
}

QString RdpX11ClipChannelServer::stringFromAtom(xcb_atom_t atom) {
	QString result;
	xcb_get_atom_name_cookie_t cookie;
	xcb_get_atom_name_reply_t *reply = NULL;
	char *buf = NULL;
	int buflen = 0;

	cookie = xcb_get_atom_name(mXcbConnection, atom);
	if ((reply = xcb_get_atom_name_reply(mXcbConnection, cookie, NULL))) {
		if ((buflen = xcb_get_atom_name_name_length(reply)) > 0) {
			if ((buf = (char *)calloc(1, buflen + 1))) {
				memcpy((void *)buf, xcb_get_atom_name_name(reply), buflen);
				result = buf;
				free(buf);
			}
		}
		free(reply);
	}
	return result;
}

xcb_atom_t RdpX11ClipChannelServer::atomFromString(const char *str, bool onlyIfExists) {
	xcb_atom_t result = XCB_ATOM_NONE;
	xcb_intern_atom_cookie_t cookie;
	xcb_intern_atom_reply_t *reply = NULL;
	uint8_t only_if_exists = onlyIfExists ? 1 : 0;

	cookie = xcb_intern_atom(mXcbConnection, only_if_exists, strlen(str), str);
	if ((reply = xcb_intern_atom_reply(mXcbConnection, cookie, NULL))) {
		result = reply->atom;
		free(reply);
	}
	return result;
}

xcb_window_t RdpX11ClipChannelServer::getSelectionOwner(xcb_atom_t atom) {
	xcb_window_t result = XCB_WINDOW_NONE;
	xcb_get_selection_owner_cookie_t cookie;
	xcb_get_selection_owner_reply_t *reply = NULL;

	cookie = xcb_get_selection_owner(mXcbConnection, atom);
	if ((reply = xcb_get_selection_owner_reply(mXcbConnection, cookie, NULL))) {
		result = reply->owner;
		free(reply);
	}
	return result;
}

void RdpX11ClipChannelServer::setSelectionOwner(xcb_atom_t atom, xcb_window_t owner) {
	xcb_set_selection_owner(mXcbConnection, owner, atom, XCB_CURRENT_TIME);
}
