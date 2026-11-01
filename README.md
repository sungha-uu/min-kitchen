# 급식 레시피 노트

급식 레시피 245종을 메뉴·재료로 검색하고, 배수를 바꿔 재료량을 환산하고, 원본 레시피 이미지와 나란히 확인하는 정적 웹페이지입니다.
[민경의 주방](https://github.com/sungha-uu/minkyoung_jian) 대시보드에서 급식 레시피만 분리했습니다.

페이지: https://sungha-uu.github.io/min-kitchen/

## 비밀번호 보호

레시피 데이터와 원본 이미지는 `vault/` 에 **AES-256-GCM으로 암호화**되어 올라가 있고, 페이지에서 비밀번호를 입력하면 브라우저 안에서 풀립니다.

- 평문 원본: `_source/` (git 제외, 이 PC에만 있음)
  - `_source/recipes.json` — 레시피 데이터
  - `_source/images/` — 원본 레시피 이미지
- 비밀번호 변경 / 데이터 수정 후 다시 암호화:

```powershell
python tools/build_vault.py 새비밀번호
git add -A; git commit -m "Update vault"; git push
```

비밀번호를 바꾸면 "이 기기에서 기억하기"로 저장된 접속도 자동으로 풀려 다시 입력해야 합니다.

## 구성

- `index.html` · `styles.css` · `app.js` — 화면 (라이트/다크 테마, 모바일 대응)
- `vault/` — 암호화된 데이터(`data.bin`)와 이미지(`img/*.bin`)
- `tools/build_vault.py` — 암호화 스크립트 (`pip install cryptography` 필요)

## 로컬 확인

```powershell
python -m http.server 4173
```
