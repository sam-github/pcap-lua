# OS X
CC = MACOSX_DEPLOYMENT_TARGET="10.3" gcc
LUA = lua
LDFLAGS = -fno-common -bundle -undefined dynamic_lookup
CLUA=-I/usr/local/include
LLUA=-l${LUA}
