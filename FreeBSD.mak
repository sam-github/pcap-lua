# FreeBSD
CC = clang
LDFLAGS = -fPIC -fno-common -shared
LUA = lua51
CLUA=-I/usr/local/include -I/usr/local/include/${LUA}
LLUA=-llua-5.1
