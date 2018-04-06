# Welcome to the ogon-channels repository

The ogon channel repository contains code for server side RDP virtual channels like
clipboard or drive redirection. The channels are Qt based and use WTS/OTSAPI for communication
with the client. It also contains some code common for all RDP channels that can be used to 
develop new and/or custom channels.

ogon-channel is part of the ogon project.

## What is the ogon project?

The ogon project is an open source driven collection of services and tools mainly written in C/C++
that provide graphical remote access to Linux desktop sessions using the Remote Desktop Protocol
(RDP). It supports most modern RDP protocol extensions, bitmap compression codecs, dis- and
reconnection to sessions and device redirections.
ogon is compatible with virtually any existing RDP Client.

Any X11 destkop, weston or qt application can be used as session. Due to it's modular
design it's easily possible to extend or add features or add new backends.

# tl;dr - too long; didn't read - I just want ...

* .. to report [a BUG][bugs]
* .. to build it - have a look at our [documentation][documentation]
* .. help - have a look to our [SUPPORT.md document][support]
* .. to get in touch - have a look to our [SUPPORT.md document][support]
* .. to contribute - have a look to [CONTRIBUTING.md][contribute]

# License

Most components of the ogon-project are licensed under the GNU AFFERO GENERAL PUBLIC LICENSE version 3.
See LICENSE file of the respective repository.

# Building

```
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/opt/ogon -DCMAKE_PREFIX_PATH=/opt/ogon/ .
make install
```

[support]: https://github.com/ogon-project/ogon-project/blob/master/SUPPORT.md
[bugs]: https://github.com/ogon-project/ogon-project/blob/master/SUPPORT.md#bugs
[documentation]: https://github.com/ogon-project/ogon-project/blob/master/SUPPORT.md#documentation
[contribute]: https://github.com/ogon-project/ogon-project/blob/master/CONTRIBUTING.md
