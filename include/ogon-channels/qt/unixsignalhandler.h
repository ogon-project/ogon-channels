/**
 * ogon - Free Remote Desktop Services
 * RDP Virtual Channel Servers
 * Unix Signal Handling Qt Class
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

#ifndef UNIXSIGNALHANDLER_H
#define UNIXSIGNALHANDLER_H

#include <QSocketNotifier>
#include <signal.h>

#define unixSignalHandler (static_cast<UnixSignalHandler *>(UnixSignalHandler::instance()))

class UnixSignalHandler : public QObject {
	Q_OBJECT

public:
	static UnixSignalHandler *instance();
	static void destroy();
	static void unixHandler(int signum);
	bool watch(int signum);

signals:
	void activated(int signum);

private:
	UnixSignalHandler();
	~UnixSignalHandler();
	UnixSignalHandler(UnixSignalHandler const&);
	UnixSignalHandler& operator=(UnixSignalHandler const&);
	QSocketNotifier *socketNotifier;

private slots:
	void socketActivated();
};

#endif /* UNIXSIGNALHANDLER_H */
