#-*- coding:utf-8 -*-

from PyQt5 import uic
from PyQt5.QtWidgets import*
from PyQt5.QtCore import*
from PyQt5.QtGui import*
from scapy.all import *
from Module import Check_connection
import os
import ctypes

def check_su():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    else:
        return '[오류] 이 명령은 관리자 권한을 사용하여 실행해야 합니다.'

def check_interface():
    interface = os.popen('netsh wlan show driver').read().split()
    if(interface[0] == '시스템에'):
        return '[네트워크] 시스템에 무선 인터페이스가 없습니다. 무선랜카드를 설치해주세요.'
    elif(interface[interface.index('호스트된') + 4] == '예'):
        return True
    else:
        return '[네트워크] 네트워크 호스트를 지원하지 않는 무선 인터페이스입니다. 다른 무선랜카드를 사용해주세요.'

def check_npcap():
    try:
        send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap', verbose=False)
        return True
    except:
        return '[Scapy] npcap을 찾을 수 없습니다. https://nmap.org/npcap/ 에서 npcap을 설치해주세요.'

def check_error():
    if(check_su() != True):
        return check_su()
    elif(check_interface() != True):
        return check_interface()
    elif(check_npcap() != True):
        return check_npcap()
    else:
        return True

error = check_error()

interface = 'Microsoft Hosted Network Virtual Adapter'

def find_ethernet_name():
    ipconfig = os.popen('ipconfig').read().split()
    try:
        while(ipconfig[ipconfig.index('이더넷') + 18] != 'IPv4'):
            ipconfig.remove('이더넷')
        return [True, f'이더넷 {ipconfig[ipconfig.index("이더넷") + 1].replace(":", "")}']
    except:
        try:
            if(ipconfig[ipconfig.index("이더넷:") + 17] == 'IPv4'):
                return [True, '이더넷']
        except:
            try:
                while (ipconfig[ipconfig.index('Wi-Fi') + 18] != 'IPv4'):
                    ipconfig.remove('Wi-Fi')
                else:
                   return [True, f'Wi-Fi {ipconfig[ipconfig.index("Wi-Fi") + 1].replace(":", "")}']
            except:
                try:
                    if (ipconfig[ipconfig.index("Wi-Fi:") + 17] == 'IPv4'):
                        return [True, 'Wi-Fi']
                except:
                    return [False, '[오류] 인터넷 공유를 사용할 수 없습니다. 네트워크 이름을 "이더넷 n" 또는 "Wi-Fi n"으로 변경해주세요.']

def find_hostednetwork_name():
    ipconfig = os.popen('ipconfig /all').read()
    return ipconfig[ipconfig.find(interface) - 70:ipconfig.find(interface) - 59].replace(':','')

def ics():
    ps1_1 = 'regsvr32 hnetcfg.dll /s;'
    ps1_2 = '$m = New-Object -ComObject HNetCfg.HNetShare;'
    ps1_3_1 = '$c = $m.EnumEveryConnection |? { $m.NetConnectionProps.Invoke($_).Name -eq "'
    ps1_3_2 = '" };'
    ps1_4 = '$config = $m.INetSharingConfigurationForINetConnection.Invoke($c);'
    ps1_5_check = 'Write-Output $config.SharingEnabled;'
    ps1_5_enable_private = '$config.EnableSharing(1)'
    ps1_5_enable_sharing = '$config.EnableSharing(0)'
    cmd_start_ps1_check = 'Powershell.exe -noprofile -executionpolicy bypass -file "C:\IPS_network_ps1\check_ics.ps1"'
    cmd_start_ps1_1 = 'Powershell.exe -noprofile -executionpolicy bypass -file "ics_cmd.ps1"'
    cmd_start_ps1_2 = 'Powershell.exe -noprofile -executionpolicy bypass -file "ics_cmd2.ps1"'
    if not os.path.isdir("C:\IPS_network_ps1"):
        os.mkdir("C:\IPS_network_ps1")
    if(find_ethernet_name()[0] == True):
        ics_check = open('C:\IPS_network_ps1\check_ics.ps1', "w")
        ics_check.write(ps1_1 + ps1_2 + ps1_3_1 + find_ethernet_name()[1] + ps1_3_2 + ps1_4 + ps1_5_check)
        ics_check.close()
    else:
        return find_ethernet_name()[1]
    if(os.popen(cmd_start_ps1_check).read().split()[0] == 'False'):
        cmd_1 = open("C:\IPS_network_ps1\ics_cmd.ps1", "w")
        cmd_1.write(ps1_1 + ps1_2 + ps1_3_1 + find_hostednetwork_name() + ps1_3_2 + ps1_4 + ps1_5_enable_private)
        cmd_1.close()
        cmd_2 = open("C:\IPS_network_ps1\ics_cmd2.ps1", "w")
        cmd_2.write(ps1_1 + ps1_2 + ps1_3_1 + find_ethernet_name()[1] + ps1_3_2 + ps1_4 + ps1_5_enable_sharing)
        cmd_2.close()
        cmd_start = open("C:\IPS_network_ps1\start_cmd.bat", "w")
        cmd_start.write(f'cd "%~dp0"\n{cmd_start_ps1_1}&&{cmd_start_ps1_2}\nExit')
        cmd_start.close()
        os.startfile('ps1\ICS.exe')
        return '[ICS] 인터넷 연결 공유가 활성화됐습니다.'
    else:
        return '[ICS] 인터넷 연결 공유가 이미 활성화되어 있습니다.'


def find_ssid():
    ssid = os.popen('netsh wlan show hostednetwork').read()
    ssid = ssid.split()
    ssid = ssid[ssid.index('SSID') + 3].split('"')
    return ssid[1]


def find_key():
    key = os.popen('netsh wlan show hostednetwork setting=security').read()
    key = key.split()
    return key[key.index('사용자') + 4]


def check_client():
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return ''
    else:
        return(c[c.index('상태') + 19])


def check_channel():
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return ''
    else:
        return(c[c.index('상태') + 15])

def check_status():
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return '꺼짐'
    else:
        return(c[c.index('상태') + 4])
    
def network_start():
    if(check_status() == '시작됨'):
        return '[네트워크] 이미 시작되어있습니다.'
    else:
        os.system('netsh wlan start hostednetwork')
        return '[네트워크] 네트워크가 시작되었습니다.'

def network_stop():
    if(check_status() == '시작됨'):
        os.system('netsh wlan stop hostednetwork')
        return '[네트워크] 네트워크가 종료되었습니다.'
    else:
        return '[네트워크] 네트워크가 시작되지 않았습니다'

def network_set(ssid, key):
    os.system(f'netsh wlan set hostednetwork mode=allow ssid={ssid} key={key}')
    if (check_status() == '시작됨'):
        return f"[설정] 네트워크 이름: {SSID} 네트워크 비밀번호: {KEY[0:4]}**** \n[설정] 재시작 시 적용됩니다."
    else:
        return f"[설정] 네트워크 이름: {SSID} 네트워크 비밀번호: {KEY[0:4]}****"

form_class = uic.loadUiType("GUI\MyWindow.ui")[0]

SSID = ' '
KEY = ' '
if(error == True):
    SSID = find_ssid()
    KEY = find_key()

image_on = 'GUI/on.png'
image_off = 'GUI/off.png'

checked = True
class MyWindow(QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


        self.Line_SSID.setText(SSID)
        self.Line_KEY.setText(KEY)

        self.SET.clicked.connect(self.netsh_set)
        self.StartNetwork.clicked.connect(self.netsh_start)
        self.StopNetwork.clicked.connect(self.netsh_stop)

        self.Line_SSID.textChanged.connect(self.SSIDchanged)
        self.Line_KEY.textChanged.connect(self.KEYchanged)

        self.Console.textChanged.connect(self.ConsoleChanged)

        self.Quit.clicked.connect(self.window_quit)
        self.Mini.clicked.connect(self.window_mini)

        self.Check_PARP.stateChanged.connect(self.chk_parp)
        self.Check_PICMP.stateChanged.connect(self.chk_picmp)
        self.Check_PSWITCHJ.stateChanged.connect(self.chk_pswitchj)

        self.Check_Button.clicked.connect(self.check_button_1)
        self.Check_Button_2.clicked.connect(self.check_button_2)
        self.Check_Button_3.clicked.connect(self.check_button_3)

        self.StartNetwork.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 80);}
            '''
        )
        self.SET.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 80);}
            '''
        )
        self.StopNetwork.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 80);}
            '''
        )
        self.Quit.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 80);}
            '''
        )
        self.Mini.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 80);}
            '''
        )


        self.oldPos = self.pos() #창없는 윈도우 드래그: 위치 변수

    #창없는 윈도우 드래그
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def mousePressEvent(self, event):
        self.oldPos = event.globalPos()

    def mouseMoveEvent(self, event):
        delta = QPoint(event.globalPos() - self.oldPos)
        self.move(self.x() + delta.x(), self.y() + delta.y())
        self.oldPos = event.globalPos()


    def window_quit(self):
        network_stop()
        sys.exit(app.exec_())

    def window_mini(self):
        self.showMinimized()

    def ConsoleChanged(self):
        if(error == True):
            self.Label_Online_2.setText(check_client())
            self.Label_Status_2.setText(check_status())
            self.Label_Channel_2.setText(check_channel())

    def SSIDchanged(self, text):
        global SSID
        SSID = text

    def KEYchanged(self, text):
        global KEY
        KEY = text

    def netsh_set(self):
        if(error == True):
            self.Console.append(network_set(SSID, KEY))
        else:
            self.Console.append(error)

    def netsh_start(self):
        def indicate_connection():
            while(check_status() == '시작됨'):
                a = Check_connection.check_connection()
                self.Console.append(f'[DHCP] [{a.split()[0]}]이(가) 연결했습니다. [{a.split()[1]}] 아이피를 할당했습니다.')
        if(error == True):
            self.Console.append(network_start())
            self.Console.append(ics())
            sniff_dhcp_thread = threading.Thread(target=indicate_connection)
            sniff_dhcp_thread.daemon = True
            sniff_dhcp_thread.start()
        else:
            self.Console.append(error)
    
    def netsh_stop(self):
        if(error == True):
            self.Console.append(network_stop())
        else:
            self.Console.append(error)

    def chk_parp(self):
        if self.Check_PARP.isChecked():
            self.CheckBox_image.setPixmap(QPixmap(image_on))
        else:
            self.CheckBox_image.setPixmap(QPixmap(image_off))

    def chk_picmp(self):
        if self.Check_PICMP.isChecked():
            self.CheckBox_image_2.setPixmap(QPixmap(image_on))
        else:
            self.CheckBox_image_2.setPixmap(QPixmap(image_off))

    def chk_pswitchj(self):
        if self.Check_PSWITCHJ.isChecked():
            self.CheckBox_image_3.setPixmap(QPixmap(image_on))
        else:
            self.CheckBox_image_3.setPixmap(QPixmap(image_off))

    def check_button_1(self):
        if self.Check_PARP.isChecked():
            self.Check_PARP.setChecked(False)
        else:
            self.Check_PARP.setChecked(True)

    def check_button_2(self):
        if self.Check_PICMP.isChecked():
            self.Check_PICMP.setChecked(False)
        else:
            self.Check_PICMP.setChecked(True)

    def check_button_3(self):
        if self.Check_PSWITCHJ.isChecked():
            self.Check_PSWITCHJ.setChecked(False)
        else:
            self.Check_PSWITCHJ.setChecked(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.setWindowFlags(Qt.FramelessWindowHint)
    myWindow.show()
    app.exec_()