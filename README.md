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
