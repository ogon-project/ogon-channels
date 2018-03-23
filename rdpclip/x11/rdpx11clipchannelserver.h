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

#ifndef RDPX11CLIPCHANNELSERVER_H
#define RDPX11CLIPCHANNELSERVER_H

#include <QApplication>
#include <QAbstractNativeEventFilter>
#include <xcb/xcb.h>

#include <ogon-channels/qt/rdpclipchannelserver.h>
#include <ogon-channels/qt/unixsignalhandler.h>


class RdpX11ClipChannelServer
	: public RDPClipChannelServer, public QAbstractNativeEventFilter
{
	Q_OBJECT

public:
	RdpX11ClipChannelServer(QApplication *app, bool useDelayedRendering, bool usePrimarySelection, QObject *parent = 0);
	~RdpX11ClipChannelServer();
	virtual bool nativeEventFilter(const QByteArray &eventType, void *message, long *) Q_DECL_OVERRIDE;

private:
	xcb_connection_t *mXcbConnection;
	xcb_atom_t mXcbClipboardManagerAtom;
	xcb_atom_t mXcbClipboardAtom;
	xcb_atom_t mXcbPrimaryAtom;
	xcb_atom_t mXcbUtf8TargetAtom;
	xcb_atom_t mXcbHtmlTargetAtom;

	QString stringFromAtom(xcb_atom_t atom);
	xcb_atom_t atomFromString(const char *str, bool onlyIfExists);
	xcb_window_t getSelectionOwner(xcb_atom_t atom);
	void setSelectionOwner(xcb_atom_t atom, xcb_window_t owner);

private slots:
	void handleUnixSignal(int signum);
};

#endif /* RDPX11CLIPCHANNELSERVER_H */
