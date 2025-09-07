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

# --- Ayarlar ---
# Bu SECRET_KEY'i kesinlikle güvenli bir yerden (örneğin ortam değişkeni) almalısın.
# 'openssl rand -hex 32' komutu ile terminalde yeni bir key üretebilirsin.
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Şifreleme ---
# Şifreleri hash'lemek için bir context oluşturuyoruz.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Bu fonksiyon, kullanıcının giriş yaparken girdiği düz metin şifre (plain_password) ile veritabanında sakladığımız hash'lenmiş şifreyi (hashed_password) karşılaştırır. 
# pwd_context.verify metodu, girilen şifreyi aynı bcrypt yöntemiyle hash'ler ve sonuçların eşleşip eşleşmediğini kontrol eder. 
# Eşleşirse True, eşleşmezse False döner.
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Girilen şifre ile hash'lenmiş şifreyi karşılaştırır."""
    return pwd_context.verify(plain_password, hashed_password)

#Bu fonksiyon, yeni bir kullanıcı kaydolduğunda veya şifresini güncellediğinde, 
# girilen düz metin şifreyi alır ve bcrypt ile hash'leyerek veritabanında saklanacak güvenli formata dönüştürür. 
# Asla şifreleri veritabanında düz metin olarak saklamamalıyız!
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
