#-*- coding:utf-8 -*-

from PyQt5 import uic
from PyQt5.QtWidgets import*
from PyQt5.QtCore import*
from PyQt5.QtGui import*    # PYQT = GUI 라이브러리
from scapy.all import *    # SCAPY = 네트워크 관련 라이브러리 
from Module import Check_connection    # MODULE 폴더에 있는 연결 감지 모듈 import
import os    # OS 관련 라이브러리
import ctypes    # 외부 함수 인터페이스 라이브러리라는데 정확히 뭔지는 모르고 관리자 권한으로 실행됬는지 확인할 때만 사용

def check_su():    # 프로그램이 관리자 권한으로 실행됬는지 확인 하는 함수
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True    # 관리자 권한이면 True 리턴
    else:
        return '[오류] 이 명령은 관리자 권한을 사용하여 실행해야 합니다.'     # 아니면 오류 메세지 리턴

def check_interface():    # 네트워크 인터페이스를 확인 하는 함수
    driver = os.popen('netsh wlan show driver').read().split()    # cmd에 netsh wlan show driver 명령어를 입력했을때 출력되는 메세지 저장
    if(driver[0] == '시스템에'):    # 무선랜 카드가 없을때 출력되는 메세지면 오류 메세지 리턴
        return '[네트워크] 시스템에 무선 인터페이스가 없습니다. 무선랜카드를 설치해주세요.'
    else:
        try:
            while(driver[driver.index('호스트된') + 4] != '예'):
                driver.remove('호스트된')
            return True    # 반복문으로 인식되어있는 모든 무선랜 카드를 확인하고 네트워크 호스트를 지원하는 무선랜카드가 있으면 True 리턴
        except:
            return '[네트워크] 네트워크 호스트를 지원하지 않는 무선 인터페이스입니다. 다른 무선랜카드를 사용해주세요.'    # 아니면 오류 메세지 리턴

def check_npcap():    # npcap이 설치되어있는지 확인하는 함수(npcap이 없으면 scapy가 작동하지 않음)
    try:
        send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap', verbose=False)    # scapy를 이용해 루프백 아이피로 icmp 패킷을 보냄
        return True    # 정상적으로 작동하면 True 리턴
    except:
        return '[Scapy] npcap을 찾을 수 없습니다. https://nmap.org/npcap/ 에서 npcap을 설치해주세요.'    # 오류가 나면 오류 메세지 리턴

def check_error():    # 에러 확인 함수
    if(check_su() != True):
        return check_su()
    elif(check_interface() != True):
        return check_interface()
    elif(check_npcap() != True):
        return check_npcap()
    else:
        return True    # 관리자 권한 확인 함수, 무선랜 카드 확인 함수, npcap 확인 함수에서 이상이 없으면 True, 오류 메시지가 있다면 그 오류 메세지를 리턴

def find_interface_name():    # 호스트 네트워크의 인터페이스 이름을 찾는 함수
    interfaces = str(ifaces)
    interfaces = interfaces.split('  ')
    for interface in interfaces:
        if not(interface.find('Microsoft Hosted Network Virtual Adapter') == -1):
            if(interface.find('#') == -1):
                return 'Microsoft Hosted Network Virtual Adapter'
            else:
                return f"Microsoft Hosted Network Virtual Adapter {interface[interface.find('#'):interface.find('#')+2]}"

error = check_error()

def find_ethernet_name():    # 인터넷 연결을 공유할 네트워크 인터페이스 이름을 찾는 함수
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

def find_hostednetwork_name():    # 호스트 네트워크의 이름을 찾는 함수
    ipconfig = os.popen('ipconfig /all').read()
    return ipconfig[ipconfig.find(find_interface_name()) - 70:ipconfig.find(find_interface_name()) - 59].replace(':','')

def ics():    # 인터넷 연결 공유를 활성화해서 실행된 네트워크에 접속했을때 정상적으로 인터넷을 할 수 있게 해주는 함수
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


def find_ssid():    # 호스트 네트워크의 무선랜 이름을 찾는 함수
    ssid = os.popen('netsh wlan show hostednetwork').read()
    ssid = ssid.split()
    ssid = ssid[ssid.index('SSID') + 3].split('"')
    return ssid[1]


def find_key():    # 호스트 네트워크의 무선랜 비밀번호 찾는 함수
    key = os.popen('netsh wlan show hostednetwork setting=security').read()
    key = key.split()
    return key[key.index('사용자') + 4]


def check_client():    # 호스트 네트워크의 접속자 수를 확인하는 함수
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return ''
    else:
        return(c[c.index('상태') + 19])


def check_channel():    # 호스트 네트워크의 채널을 확인하는 함수
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return ''
    else:
        return(c[c.index('상태') + 15])

def check_status():    # 호스트 네트워크가 켜져있는지 확인하는 함수
    c = os.popen('netsh wlan show hostednetwork').read()
    c = c.split()
    if(c[c.index('상태') + 5] == '안'):
        return '꺼짐'
    else:
        return(c[c.index('상태') + 4])
    
def network_start():    # 호스트 네트워크를 시작하는 함수 
    if(check_status() == '시작됨'):
        return '[네트워크] 이미 시작되어있습니다.'
    else:
        os.system('netsh wlan start hostednetwork')
        return '[네트워크] 네트워크가 시작되었습니다.'

def network_stop():    # 호스트 네트워크를 종료하는 함수
    if(check_status() == '시작됨'):
        os.system('netsh wlan stop hostednetwork')
        return '[네트워크] 네트워크가 종료되었습니다.'
    else:
        return '[네트워크] 네트워크가 시작되지 않았습니다'

def network_set(ssid, key):    # 이름, 비밀번호 값을 받아서 설정하는 함수
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
                a = Check_connection.check_connection(find_interface_name())
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