#ifndef ARPSCANTHREAD_H
#define ARPSCANTHREAD_H

#define HAVE_REMOTE
#include "pcap.h"
#include <QObject>
#include <QThread>
#include <IP_Range.h>
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
    void SetScanRange(QString Begin_IP,QString End_IP,QString Mask) throw();
    void SetScanSrcMac(QString Mac);
signals:
  SendData(QByteArray Data);
  SendError(QString ErrorInfo);
  SendStatu(QString Status);
private:
  void run();
  IP_Range *_IP_Range;
  bool _IsStop;
  Raw_Mac _Src_Mac;
  pcap_t* _Scan_fp;
  char* _Err_Buf;
  QString _Dev_Name;
};

#endif // ARPSCANTHREAD_H
