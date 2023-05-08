# JCode

JCode는 JCloud 인스턴스를 통해 생성할 수 있는 VSCode기반 온라인 IDE입니다. 

한번 생성해서 어디서든 브라우저를 통해 내 IDE를 사용할 수 있습니다. 

<img src="./resource/InstallGuide/1.png" width="600px" height="300px"/> <br /> <br /> <br />

# 설치

1. **먼저, JCloud인스턴스를 생성합니다.** 

    ❗JCloud 설치 방법은 아래 문서를 참고해주세요

    [JCloud 인스턴스 생성 매뉴얼.pdf](JCode%20%E1%84%89%E1%85%A1%E1%84%8B%E1%85%AD%E1%86%BC%20%E1%84%86%E1%85%A2%E1%84%82%E1%85%B2%E1%84%8B%E1%85%A5%E1%86%AF%206a08193381f94bbf807a9e9a99decb11/jcloud.creating.instance.student.2019.v2.pptx.pdf)

<br/>

2. **터미널 또는 Putty와 같은 SSH도구를 통해 JCloud 인스턴스에 접속합니다.** 

    ```bash
    ssh ubuntu@[IP] -i [Keyname].pem -p [Port Number]
    ```

    <img src="./resource/InstallGuide/2.png" width="600px" height="auto"/> <br/><br/><br/>

3. **아래 명령어를 통해 JCode 저장소를 Clone합니다.**

    ```bash
    git clone https://github.com/JBNU-JEduTools/JCode
    ```

    <img src="./resource/InstallGuide/3.png" width="600px" height="auto"/> <br/><br/><br/>

4. **아래 명령어를 통해 JCode 디렉터리로 이동 후, 설치스크립트를 실행합니다.**

    ```bash
    cd JCode        # JCode 디렉터리로 이동
    ./install.sh    # JCode 설치 스크립트 실행
    ```

    <img src="./resource/InstallGuide/4.png" width="600px" height="auto"/> <br/><br/><br/>

    ❗**설치 스크립트에서는 사용하는 언어의 확장 프로그램을 선택해 설치할 수 있습니다.**

    해당하는 언어의 번호를 눌러 확장 프로그램을 설치하고, 마지막에 0을 눌러 설치를 종료합니다.

    설치를 마치면, Successfully installed라는 메시지와 함께 실행을 종료합니다. 

    <img src="./resource/InstallGuide/5.png" width="600px" height="auto"/> <br/><br/><br/>

5. **아래 명령어를 통해 Code Server를 실행합니다.**

    ```bash
    nohup code-server &
    ```

    이제, 브라우저에 [인스턴스 IP주소]:8080 를 입력해 나만의 IDE로 접근할 수 있습니다. 

    <img src="./resource/InstallGuide/6.png" width="600px" height="auto"/> <br/><br/><br/>

    기본 설정은 아래와 같습니다.

    ```bash
    # cat .config/code-server/config.yaml 
    bind-addr: 0.0.0.0:8080
    auth: password
    cert: false
    password: 2218
    ```

    - 포트: 8080
    - 비밀번호: 2218

    **만약 설정을 바꾸고싶다면**

    .config/code-server/config.yaml 파일을 수정한 후, Code-Server를 재시작하면 됩니다.


# Note

### 스크립트 정보

- install.sh : JCloud 에서 Ubuntu image 를 기반으로 Watcher client 등 관련 도구를 설치하고 환경을 설정하는 스크립트 
- install_jota_agent.sh : 자동 채점 서비스 JOTA와의 연동을 수행하는 extension 을 설치하는 스크립트 (install_jcode.sh 에 포함)
- install_extensions.sh : JCode 에서 사용할 언어 및 환경들을 자동으로 설치하는 스크립트


### 추가정보

- 현재 Watcher server 의 IP 주소는 10.0.0.254 로 고정되어 있음
- install.sh 는 ubuntu 계정으로 수행하여야 함
- ⚠ C/C++ Extension을 사용하려는 경우 [Install_VSIX.md][1] 를 참고하여 설치하여야 제대로 작동함.
- JCode에서 실행가능 한 Extension에 대해서 궁금하신 경우 [Extension_For_JCode][2] 를 참고.
- JCode에서 C/C++ 환경 설정 및 Debugging 을 수행하려는 경우 [C/C++ Setting For JCode][3] 를 참고.

[1]: https://github.com/GangSSun/JCode/blob/dd075dbd3eeef236084842b097bb3212a49f5855/Install_By_VSIX.md "Install_VSIX"
[2]: https://github.com/GangSSun/JCode_Extension_Documentation/blob/99d8aa389d94fedcf78c8c9e96ca916ab9047654/README.md "Extension For JCode"
[3]: https://github.com/brixno/JCode/blob/main/Setting_C_C++.md ""