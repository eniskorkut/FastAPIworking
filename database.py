from fastapi import HTTPException

from typing import Dict, Any, Optional
from models import UserInDB

# Veritabanı yerine kullanacağımız sahte kullanıcı verisi
# Bu, normalde gerçek bir veritabanı bağlantısı ve sorgusu olurdu.
# Döngüsel import hatasını önlemek için auth modülünü import etmiyoruz.
# Hash'lenmiş şifreyi elle giriyoruz. Bu şifre "1234"ün bcrypt hash'idir.
fake_users_db = {
    "eniskorkut": {
        "username": "eniskorkut",
        "full_name": "Enis Korkut",
        "email": "enis@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fC51JmvT3hGz.o.sspG3Tj6g2f2yNsa2T22iMv2wzW/e",
        "disabled": False,
    }
}


def get_user(db: Dict[str, Any], username: str) -> Optional[UserInDB]:
    """
    Veritabanından (sözlükten) kullanıcıyı bulur ve UserInDB modeline dönüştürür.
    Kullanıcı bulunamazsa None döndürür.
    """
    if username in db:
        user_dict = db[username]
        # **user_dict, sözlükteki anahtar-değer çiftlerini modelin
        # alanlarına atar (username="eniskorkut", full_name=... vb.)
        return UserInDB(**user_dict)
    return None
