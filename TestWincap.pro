#-------------------------------------------------
#
# Project created by QtCreator 2016-03-08T18:59:38
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = TestWincap
TEMPLATE = app

QMAKE_CFLAGS += -std=gnu11  -D_GNU_SOURCE
QMAKE_CXXFLAGS += -std=gnu++11

LIBS += -L$$PWD/WinPcap/Lib/ -lpacket -lwpcap

LIBS += -LD:\Qt\Qt5.5.1\Tools\mingw492_32\i686-w64-mingw32\lib\ -lws2_32

SOURCES += main.cpp\
        mainwindow.cpp \
    ArpScanThread.cpp \
    CaptureThread.cpp \
    NetProtocol.c \
    IP_Range.cpp \
    NetTools.c \
    NetProtocolTools.cpp

HEADERS  += mainwindow.h \
    ArpScanThread.h \
    CaptureThread.h \
    NetProtocol.h \
    NetTools.h \
    IP_Range.h \
    NetProtocolTools.h

FORMS    += mainwindow.ui

INCLUDEPATH += $$PWD/WinPcap/Include
DEPENDPATH += $$PWD/WinPcap/Include
