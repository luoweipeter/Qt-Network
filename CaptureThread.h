#ifndef ARPCAPTURETHREAD_H
#define ARPCAPTURETHREAD_H

#define HAVE_REMOTE
#include "pcap.h"
#include <QThread>
#include <QByteArray>
#include <QBuffer>
class CaptureThread:public QThread
{
    Q_OBJECT
   public:
    CaptureThread(){
        this->_IsStop=false;
    }
    CaptureThread(QString Dev_Name):_Dev_Name(Dev_Name){}
    void SetDevName(QString Dev_Name)
    {
        this->_Dev_Name=Dev_Name;
        this->_IsStop=false;
    }
    void SetParseRule(QString Rule)
    {
        _Parse_Rule=Rule;
    }
    void SetMask(QString Mask)
    {
        _Mask=Mask;
    }
    void ShutDown()
    {
        this->_IsStop=true;
    }
   signals:
     SendData(QByteArray Data);
     SendError(QString ErrorInfo);
     SendStatu(QString Status);
   private:
     void run();

     bool _IsStop;
     pcap_t* _Cap_fp;
     char* _Err_Buf;
     QString _Mask;
     QString _Parse_Rule;
     QString _Dev_Name;
};

#endif // ARPCAPTURETHREAD_H
