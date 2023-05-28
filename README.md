# JCode
JCloud 에서 VS-Code 기반 Web-IDE 를 제공하기 위한 프로젝트 입니다. 
- install.sh : JCloud 에서 Ubuntu image 를 기반으로 Watcher client 등 관련 도구를 설치하고 환경을 설정하는 스크립트 
- install_jota_agent.sh : 자동 채점 서비스 JOTA와의 연동을 수행하는 extension 을 설치하는 스크립트 (install_jcode.sh 에 포함)
- install_extensions.sh : JCode 에서 사용할 언어 및 환경들을 자동으로 설치하는 스크립트

## Ubuntu 인스턴스에 설치: install.sh
1. JCloud 에서 최신 Ubuntu image 를 이용하여 인스턴스 생성
2. SSH 접속 후 아래 명령 수행

```
$ git clone https://github.com/hyunchan-park/JCode.git
$ cd JCode
$ ./install.sh
```
3. 설치할 언어들을 선택
```
Choose the extension you want to install. If not, press 0

	-available extension

1. C/C++
2. JAVA
3. Python
...            
```

4. JCloud 에서 제공하는 주소 및 포트 번호를 통해 JCode 접속  
   (예. cse-students 프로젝트의 경우, 브라우저에서 203.254.143.217:10xxx 로 접속.  
   xxx는 cse-students 내부 네트워크에서 본인 IP 주소 끝자리. 10.0.0.xxx)

5. 성공한 경우 출력 예

```
Ubuntu 20.04.2 LTS
Installing v3.11.0 of the amd64 deb package from GitHub.

+ mkdir -p ~/.cache/code-server
+ curl -#fL -o ~/.cache/code-server/code-server_3.11.0_amd64.deb.incomplete -C - https://github.com/cdr/code-server/releases/download/v3.11.0/code-server_3.11.0_amd64.deb
######################################################################## 100.0%##O#- #                          ######################################################################## 100.0%
+ mv ~/.cache/code-server/code-server_3.11.0_amd64.deb.incomplete ~/.cache/code-server/code-server_3.11.0_amd64.deb
+ sudo dpkg -i ~/.cache/code-server/code-server_3.11.0_amd64.deb
Selecting previously unselected package code-server.
(Reading database ... 69052 files and directories currently installed.)
Preparing to unpack .../code-server_3.11.0_amd64.deb ...
Unpacking code-server (3.11.0) ...
Setting up code-server (3.11.0) ...

deb package has been installed.

To have systemd start code-server now and restart on boot:
  sudo systemctl enable --now code-server@$USER
Or, if you don't want/need a background service you can run:
  code-server
Created symlink /etc/systemd/system/default.target.wants/code-server@ubuntu.service → /lib/systemd/system/code-server@.service.
Waiting for creating config.yaml...
Done!
Created symlink /etc/systemd/system/multi-user.target.wants/watcher.service → /etc/systemd/system/watcher.service.
Installing extensions...                                          #install_jota_agent.sh 를 실행
Extension 'jcode-jota.vsix' was successfully installed.           #jcode-jota extension의 설치 성공
```

# Note
- 현재 Watcher server 의 IP 주소는 10.0.0.254 로 고정되어 있음
- install.sh 는 ubuntu 계정으로 수행하여야 함
- ⚠ C/C++ Extension을 사용하려는 경우 [Install_VSIX.md][1] 를 참고하여 설치하여야 제대로 작동함.
- JCode에서 실행가능 한 Extension에 대해서 궁금하신 경우 [Extension_For_JCode][2] 를 참고.
- JCode에서 C/C++ 환경 설정 및 Debugging 을 수행하려는 경우 [C/C++ Setting For JCode][3] 를 참고.

[1]: https://github.com/GangSSun/JCode/blob/dd075dbd3eeef236084842b097bb3212a49f5855/Install_By_VSIX.md "Install_VSIX"
[2]: https://github.com/GangSSun/JCode_Extension_Documentation/blob/99d8aa389d94fedcf78c8c9e96ca916ab9047654/README.md "Extension For JCode"
[3]: https://github.com/brixno/JCode/blob/main/Setting_C_C++.md ""
