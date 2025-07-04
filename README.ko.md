# abugo

Go로 작성된 간단한 커맨드 라인 도구로, Android 백업 (`.ab`) 파일의 압축을 해제(unpack)합니다.

이 도구는 안드로이드 디버그 브릿지(ADB)를 사용하여 생성된 백업의 내용을 추출하기 위해 설계되었으며, 다양한 백업 버전, 압축 및 암호화를 지원합니다.

## 주요 기능

*   Android 백업 (`.ab`) 파일을 표준 TAR 아카이브로 압축 해제합니다.
*   Android 백업 버전 V1부터 V5까지 지원합니다.
*   zlib 압축이 적용된 경우 자동으로 처리합니다.
*   AES-256으로 암호화된 백업을 해독합니다 (올바른 비밀번호 필요).
*   커맨드 라인 인자 또는 `ABUGO_PASSWD` 환경 변수를 통해 비밀번호 입력을 지원합니다.
*   파일 또는 표준 입력(stdin)으로부터 백업 데이터를 읽을 수 있습니다.
*   추출된 TAR 아카이브를 파일 또는 표준 출력(stdout)으로 쓸 수 있습니다.

## 빌드

Go (버전 1.18 이상 권장)가 설치되어 있는지 확인하세요.

```bash
# 저장소를 복제합니다 (아직 하지 않았다면)
# git clone <저장소_URL>
# cd abugo

# 실행 파일 빌드
go build .
```

현재 디렉토리에 `abugo` (Windows의 경우 `abugo.exe`)라는 이름의 실행 파일이 생성됩니다.

## 사용법

주요 명령어는 `unpack` 입니다:

```
./abugo unpack <입력.ab> <출력.tar> [비밀번호]
```

**인자:**

*   `<입력.ab>`: Android 백업 파일 (`.ab`)의 경로. 표준 입력(stdin)에서 읽으려면 `-`를 사용하세요.
*   `<출력.tar>`: 추출된 TAR 아카이브를 저장할 경로. 표준 출력(stdout)으로 쓰려면 `-`를 사용하세요.
*   `[비밀번호]`: (선택 사항) 암호화된 백업을 해독하기 위한 비밀번호입니다.

**비밀번호 처리:**

백업이 암호화된 경우:

1.  마지막 커맨드 라인 인자로 비밀번호를 직접 제공할 수 있습니다.
2.  비밀번호 인자가 생략된 경우, `abugo`는 `ABUGO_PASSWD` 환경 변수를 확인하고 설정되어 있다면 해당 값을 사용합니다.
3.  백업이 암호화되어 있지만 인자나 환경 변수를 통해 비밀번호가 제공되지 않으면, 도구는 오류를 발생시키고 종료됩니다.

## 예시

**1. 암호화되지 않은 백업 파일 압축 해제:**

```bash
./abugo unpack my_backup.ab my_backup.tar
```

**2. 암호화된 백업 파일 압축 해제 (비밀번호를 인자로 전달):**

```bash
./abugo unpack secure_backup.ab secure_backup.tar 내비밀번호123
```

**3. 암호화된 백업 파일 압축 해제 (환경 변수를 통해 비밀번호 전달):**

```bash
export ABUGO_PASSWD="내비밀번호123"
./abugo unpack secure_backup.ab secure_backup.tar
# 필요하다면 나중에 변수 설정을 해제합니다
unset ABUGO_PASSWD
```

**4. 표준 입력에서 표준 출력으로 압축 해제 (예: ADB에서 직접 파이핑):**

```bash
# 백업이 암호화된 경우 비밀번호를 제공해야 합니다
adb backup -f - com.example.app | ./abugo unpack - backup.tar [필요시_비밀번호_입력]
```

**5. 파일에서 표준 출력으로 압축 해제 (예: `tar` 명령어로 파이핑):**

```bash
./abugo unpack my_backup.ab - [필요시_비밀번호_입력] | tar tvf -
```
