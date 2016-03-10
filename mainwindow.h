#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QMap>
#include <QMessageBox>
#include <QToolTip>
#define HAVE_REMOTE
#include "pcap.h"
#include "ArpScanThread.h"
#include "CaptureThread.h"
#include <QByteArray>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
private slots:
    void on_comboBox_highlighted(const QString &arg1);
    void on_SendError(QString Error);
    void on_SendData(QByteArray Data);
    void on_SendStatu(QString Info);
    void on_BeginListen_Btn_clicked();
    void on_SelectDev_Btn_clicked();
    void on_StopLinsten_Btn_clicked();

    void on_Scan_Begin_Btn_clicked();

private:
    CaptureThread *arp_capture;
    ArpScanThread *arp_scan;
    Ui::MainWindow *ui;
    QMap<QString,QString> devs_map;
    QLabel *stat;
    void FillSelect();

};

#endif // MAINWINDOW_H
