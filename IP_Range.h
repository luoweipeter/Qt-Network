#ifndef IP_RANGE_H
#define IP_RANGE_H
#include <QException>
#include "NetTools.h"
class IP_Range
{
public:
    IP_Range(QString Begin_IP,QString End_IP,QString Mask);
    long Length();
    bool HaveNext();
    unsigned long NextRawIP();
private:
    long _Length;
    long _Index;
    unsigned long _Cur_IP;
    unsigned long _Begin_IP;
    unsigned long _End_IP;
    unsigned long _Mask;
    unsigned long _Net_Addr;
    unsigned long _Broad_Addr;
};

class IP_RangeException:public QException
{
public:
    IP_RangeException(QString Info)
    {
        _Info=Info;
    }
    void raise() const {throw *this;}
    IP_RangeException *clone() const {
        return new IP_RangeException(*this);}
    ~IP_RangeException () throw();
private:
    QString _Info;
};
#endif // IP_RANGE_H
