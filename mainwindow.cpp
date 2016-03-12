#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    FillSelect();

    stat=new QLabel;
    stat->setMinimumSize(stat->sizeHint());
    stat->setAlignment(Qt::AlignHCenter);
    ui->statusBar->setStyleSheet(QString("QStatusBar::item{border:0px}"));
    ui->statusBar->addWidget(stat);

    arp_capture=new CaptureThread;
    arp_capture->SetParseRule("arp and ether dst 00:26:C7:30:BD:F8");
    arp_capture->SetMask("255.255.255.0");
    connect(arp_capture,SIGNAL(SendStatu(QString)),this,SLOT(on_SendStatu(QString)));
    connect(arp_capture,SIGNAL(SendError(QString)),this,SLOT(on_SendError(QString)));
    connect(arp_capture,SIGNAL(SendData(QByteArray)),this,SLOT(on_SendData(QByteArray)));
    arp_scan=new ArpScanThread;
    connect(arp_scan,SIGNAL(SendError(QString)),this,SLOT(on_Scan_Error(QString)));
    connect(arp_scan,SIGNAL(SendStatu(QString)),this,SLOT(on_Scan_Statu(QString)));
}

MainWindow::~MainWindow()
{
    delete ui;
    delete stat;
    arp_capture->quit();
    arp_capture->wait();
}
void MainWindow::FillSelect()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
            QMessageBox::warning(0,"Error","Error in pcap_findalldevs_ex");
    }
    for(d= alldevs; d != NULL; d= d->next)
    {
           QString name=d->name;
           QString desp=d->description;

            if (d->description)
            {
                //printf(" (%s)\n", d->description);
                desp=d->description;
            }
            else
                 desp=d->description;

            devs_map.insert(name,desp);
            ui->comboBox->addItem(name);
    }
        /* 不再需要设备列表了，释放它 */
        pcap_freealldevs(alldevs);
}



void MainWindow::on_comboBox_highlighted(const QString &arg1)
{
   QString desp=devs_map[arg1];
   stat->setText(desp);
    //QMessageBox::information(0,"Test","comboBox_highlighted");
}
void MainWindow::on_SendError(QString Error)
{
    QMessageBox::information(0,"Error",Error);
}
void MainWindow::on_SendData(QByteArray Data)
{
    QString Packet_len;
    Packet_len=QString::number(Data.length());
    ui->listWidget->addItem("收到"+Packet_len+"字节~!");
}
void MainWindow::on_SendStatu(QString Info)
{
    stat->setText(Info);
}

 void MainWindow::on_Scan_Error(QString Error)
 {
    QMessageBox::information(0,"Error",Error);
 }
 void MainWindow::on_Scan_Statu(QString Statu)
 {
     qDebug()<<Statu;
 }
void MainWindow::on_BeginListen_Btn_clicked()
{
    QString Combox_text;
    Combox_text=ui->comboBox->currentText();
    QMessageBox::information(0,"通知",Combox_text+"开始启动");
    arp_capture->SetDevName(Combox_text);
    arp_capture->start();
}
void MainWindow::on_StopLinsten_Btn_clicked()
{
    arp_capture->ShutDown();
    arp_capture->quit();
}
void MainWindow::on_SelectDev_Btn_clicked()
{
   ui->SelectDev_Btn->setEnabled(false);
   ui->comboBox->setEnabled(false);
}


void MainWindow::on_Scan_Begin_Btn_clicked()
{
    QString Combox_text;
    Combox_text=ui->comboBox->currentText();
    arp_scan->SetScanRange(ui->IP_Begin_Edt->text(),ui->IP_End_Edt->text(),ui->Mask_Edt->text());
    arp_scan->SetScanSrcMac("C8-0A-A9-5B-99-40");
    arp_scan->SetScanIP("192.168.3.13");
    arp_scan->SetDevName(Combox_text);
    arp_scan->start();
}
