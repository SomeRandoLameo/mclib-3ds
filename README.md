# mclib-3ds
C++ library for connecting to Minecraft servers on the Nintendo3DS

## Features
- Full protocol for Minecraft 1.10 through 1.12.2
- Premium (*THE MS AUTH IS NOT YET SUPPORTED*) and offline mode
- Yggdrasil API (*THE MS AUTH IS NOT YET SUPPORTED*)
- Logging in with passwords or tokens (*THE MS AUTH IS NOT YET SUPPORTED*)
- Encryption
- Compression
- Log in to Forge servers (*THE MS AUTH IS NOT YET SUPPORTED*)
- World data
- Entity data
- Basic inventory use
- NBT data
- Block entity data
- Block collisions
- Basic player controller for moving around

## Building

Dependencies:  
- C++ compiler (cmake)
- 3DS Portlibs

TODOS:
| Feature | State | Comment |
|---------|-------|---------|
| Add more usage examples | in progress | More examples would be nice in order to propperly understand MCLib |
| Add more versions | planned | Would be really cool to connect from "the oldest servers supported version" to "the newest server versions" |
| 3DS performance optimisations | planned | This library needs to be debloated heavily, if possible.  |

## Examples
- [terracotta](https://github.com/plushmonkey/Terracotta) : OpenGL client
- [client](https://github.com/plushmonkey/mclib/blob/master/client/main.cpp) : Basic example client for connecting to a server
- [mcbot](https://github.com/plushmonkey/mcbot) : Bot with pathfinding and melee attacking
- [avalanche](https://github.com/plushmonkey/avalanche) : Server stress test tool
- [mcqt](https://github.com/plushmonkey/mcqt) : Chat client made with qt
