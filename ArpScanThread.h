#ifndef ARPSCANTHREAD_H
#define ARPSCANTHREAD_H

#define HAVE_REMOTE
#include "pcap.h"
#include <QObject>
#include <QThread>
#include "NetProtocolTools.h"
#include "IP_Range.h"
class ArpScanThread:public QThread
{
    Q_OBJECT
public:
    ArpScanThread():_IsStop(false){}
    ArpScanThread(QString Devname):_Dev_Name(Devname),_IsStop(false){}
    void ShutDown()
    {
        this->_IsStop=true;
    }
    void SetDevName(QString Dev_Name)
    {
        this->_Dev_Name=Dev_Name;
        this->_IsStop=false;
    }
    void SetScanRange(QString Begin_IP,QString End_IP,QString Mask) throw();
    void SetScanSrcMac(QString Mac);
    void SetScanIP(QString IP);
signals:
  SendData(QByteArray Data);
  SendError(QString ErrorInfo);
  SendStatu(QString Status);
private:
  void run();
  IP_Range *_IP_Range;
  bool _IsStop;
  Raw_Mac _Src_Mac;
  unsigned long _Src_IP;
  pcap_t* _Scan_fp=NULL;
  char* _Err_Buf;
  QString _Dev_Name;
  int _OpenPcap();
};

#endif // ARPSCANTHREAD_H
