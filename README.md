# Healthmate
<div align="center">
<img width="329" alt="image" src="https://github.com/user-attachments/assets/c7a770da-0877-4d69-b0ed-67e8018242b4">
</div>

# Healthmate v1.0
> **개발 기간** : 2024년 1월 8일 ~ 2024년 1월 12일 <br>
> **서비스 목적** : AI를 통한 빠른 건강관리 루틴 및 식단 추천 <br>

헬스메이트는 건강관리 및 식단을 추천해주는 서비스입니다. 운동 목적을 입력하고 일주일 간 운동 횟수를 입력하면, 프로필을 분석하여 사용자에게 알맞는 건강 관리 루틴과 식단을 추천해줍니다. 구체적인 목표를 입력하면 더 상세한 정보를 얻을 수 있습니다!

## 시작 가이드
### Installation
``` bash
$ git clone https://github.com/Health-Mate-project/healthmate.git
$ cd healthmate
```
#### 가상환경 설정 및 라이브러리 설치
```
$ python -m venv venv
$ Mac: . ./venv/bin/activate
$ Window: .\venv\Scripts\activate
$ pip install -r requirements.txt
```
#### 서버 실행(택 1)
```
$ fastapi dev main.py
$ uvicorn main:app --reload
```

Stacks 🐈

### Environment
![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-007ACC?style=for-the-badge&logo=Visual%20Studio%20Code&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=Git&logoColor=white)
![Github](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=GitHub&logoColor=white)             

### Config
![pip](https://img.shields.io/badge/pip-CB3837?style=for-the-badge&logo=pip&logoColor=white)        

### Development
![HTML](https://img.shields.io/badge/html5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/css-663399?style=for-the-badge&logo=css&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=Javascript&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)

### Communication
![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=Discord&logoColor=white)
![Gather](https://img.shields.io/badge/Gather-000000?style=for-the-badge&logo=Gather&logoColor=white)

## DB 설계도
<div style="backgroundColor: .white;">
<img width="500" alt="image" src="https://github.com/user-attachments/assets/4fbe2308-eee8-4310-9a4a-402cf17f0376">
</div>

## 화면 구성 📺

## 디렉토리 구조 📁(개발 완료 후, 업데이트 예정)
```bash
┣━ 📄README.md
┣━ 📄main.py
┣━ 📁venv/ # 가상환경
┣━ 📁app/ # 애플리케이션 코드를 포함하는 폴더
┃   ┣━ 📁models/ # 데이터베이스 모델을 정의하는 파일을 포함하는 폴더
┃   ┣━ 📁routers/ # API 라우트를 정의하는 파일들 포함하는 폴더
┃   ┗━ 📁schemas/ # Pydantic 모델을 정의하는 파일들 포함하는 폴더
┗━ 📄requirements.txt # 프로젝트에서 사용하는 패키지 목록
```
