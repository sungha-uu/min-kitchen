"""레시피 데이터와 원본 이미지를 비밀번호로 암호화해 vault/ 폴더에 저장한다.

평문 원본은 _source/ (git 제외)에 둔다.
  _source/recipes.json   레시피 데이터
  _source/images/        원본 레시피 이미지 (파일명 = recipes.json 의 image 값)

사용법 (비밀번호를 바꿀 때도 같은 명령을 새 비밀번호로 다시 실행):
  python tools/build_vault.py <비밀번호>
"""
import base64
import hashlib
import json
import os
import shutil
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "_source")
VAULT = os.path.join(ROOT, "vault")
ITERATIONS = 310_000
MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}


def seal(aes: AESGCM, plain: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, plain, None)


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1]:
        sys.exit("사용법: python tools/build_vault.py <비밀번호>")
    password = sys.argv[1].encode("utf-8")
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, dklen=32)
    aes = AESGCM(key)

    with open(os.path.join(SOURCE, "recipes.json"), encoding="utf-8") as f:
        recipes = json.load(f)

    shutil.rmtree(VAULT, ignore_errors=True)
    os.makedirs(os.path.join(VAULT, "img"))

    # 이미지 파일 이름은 순번으로만 남겨 메뉴명이 드러나지 않게 한다.
    for index, recipe in enumerate(recipes):
        name = recipe.pop("image", None)
        if not name:
            continue
        with open(os.path.join(SOURCE, "images", name), "rb") as f:
            blob = seal(aes, f.read())
        file = f"{index:03d}.bin"
        with open(os.path.join(VAULT, "img", file), "wb") as f:
            f.write(blob)
        recipe["image"] = {"file": file, "type": MIME[os.path.splitext(name)[1].lower()]}

    with open(os.path.join(VAULT, "data.bin"), "wb") as f:
        f.write(seal(aes, json.dumps(recipes, ensure_ascii=False, separators=(",", ":")).encode("utf-8")))
    with open(os.path.join(VAULT, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iterations": ITERATIONS, "salt": base64.b64encode(salt).decode()}, f)

    print(f"암호화 완료: 레시피 {len(recipes)}개, 이미지 {sum(1 for r in recipes if r.get('image'))}개 -> vault/")


if __name__ == "__main__":
    main()
