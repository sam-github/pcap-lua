# Linux
CC = gcc
LDFLAGS = -fPIC -fno-common -shared
LUA = lua5.1
CLUA=$(shell pkg-config --cflags ${LUA})
LLUA=$(shell pkg-config --libs ${LUA})

