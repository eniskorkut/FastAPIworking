# auth.py
#JWT token'larının son kullanma tarihlerini (exp claim) hesaplamak için kullanılır. 
# Zamanla ilgili işlemler için standart Python kütüphaneleridir.
from datetime import datetime, timedelta, timezone
#Bir fonksiyon parametresinin veya bir model alanının isteğe bağlı olabileceğini belirtmek için kullanılır.
from typing import Optional
#passlib kütüphanesinden gelir. 
# Şifreleri hash'lemek (karmaşık ve geri döndürülemez bir metne çevirmek) ve doğrulamak için kullanılır.
from passlib.context import CryptContext
#jwt: python-jose kütüphanesinden gelir. JWT (JSON Web Token) oluşturmak (encode) ve doğrulamak/çözmek (decode) için kullanılır. 
#JWTError ise token işlemleri sırasında oluşabilecek hataları yakalamak içindir.
from jose import JWTError, jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

import database
from models import TokenData, UserInDB

# --- Ayarlar ---
# Bu SECRET_KEY'i kesinlikle güvenli bir yerden (örneğin ortam değişkeni) almalısın.
# 'openssl rand -hex 32' komutu ile terminalde yeni bir key üretebilirsin.
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 şeması, token'ın "Authorization: Bearer <token>" başlığından alınacağını
# ve token alma URL'sinin "/login" olduğunu belirtir.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# --- Şifreleme ---
# Şifreleri hash'lemek için bir context oluşturuyoruz.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Girilen şifre ile hash'lenmiş şifreyi karşılaştırır."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Girilen şifreyi hash'ler."""
    return pwd_context.hash(password)

# --- JWT Token ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Verilen data için bir JWT access token oluşturur."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Kullanıcı Doğrulama ---
def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """
    Gelen istekteki JWT token'ını doğrular, içindeki kullanıcı adını alır
    ve veritabanından ilgili kullanıcıyı bulup döndürür.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Token'ı, SECRET_KEY ve ALGORITHM kullanarak çözmeye çalış.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Token içindeki "sub" (subject) alanını (yani kullanıcı adını) al.
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        # Token verisini Pydantic modeli ile doğrula.
        token_data = TokenData(username=username)
    except JWTError:
        # Token çözülemezse (geçersiz, süresi dolmuş vb.) hata fırlat.
        raise credentials_exception

    # Token'dan gelen kullanıcı adıyla veritabanından kullanıcıyı getir.
    # Yukarıdaki try bloğunda username'in None olmadığını kontrol ettik,
    # bu yüzden burada None olma ihtimali yok.
    assert token_data.username is not None
    user = database.get_user(database.fake_users_db, username=token_data.username)
    if user is None:
        # Token geçerli olsa bile, o kullanıcı artık veritabanında yoksa hata fırlat.
        raise credentials_exception
    return user


def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """
    get_current_user'dan gelen kullanıcıyı alır ve hesabının "disabled" olup olmadığını
    kontrol eder. Eğer pasif bir kullanıcıysa, erişimi engeller.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
