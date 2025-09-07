#FastAPI: Uygulamamızın ana sınıfı.
#Depends: FastAPI'nin "Dependency Injection" sistemini kullanmamızı sağlar. 
# OAuth2PasswordRequestForm gibi hazır bağımlılıkları fonksiyonlarımıza enjekte etmek için kullanacağız.
#HTTPException, status: Kullanıcı adı/şifre yanlış olduğunda 401 Unauthorized gibi standart HTTP hataları fırlatmak için gereklidir.
#timedelta: Token'ın geçerlilik süresini belirlemek için kullanılır.
#OAuth2PasswordRequestForm: Standart bir "kullanıcı adı ve şifre" formundan gelen veriyi yakalamak için FastAPI'nin sağladığı özel bir sınıftır.
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from auth import create_access_token, get_password_hash, verify_password
from models import Token, User, UserInDB


app = FastAPI() # Tüm API endpoint'lerimizi (@app.get, @app.post vb.) bu app nesnesi üzerinden tanımlayacağız.


fake_users_db = {
    "eniskorkut": {
        "username": "eniskorkut",
        "full_name": "Enis Korkut",
        "email": "enis@example.com",
        "hashed_password": get_password_hash("1234"),  # Şifreyi burada hash'liyoruz.
        "disabled": False, # Kullanıcı hesabının aktif olup olmadığını belirtir.
    }
}

def get_user(db: dict, username: str) -> UserInDB:
    """
    Veritabanından kullanıcıyı bulur ve UserInDB modeline dönüştürür.
    Kullanıcı bulunamazsa 404 HTTPException fırlatır.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)  # UserInDB modeline dönüştürür.
    raise HTTPException(status_code=404, detail="User not found") # Kullanıcı bulunamazsa 404 hatası fırlatır.

ACCESS_TOKEN_EXPIRE_MINUTES = 30

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # kullanıcı adı ve şifre ile giriş yaparak JWT token alır.
    # 1. kullanıcının veritabanında olup olmadığını kontrol et
    # get_user fonksiyonu kullanıcıyı bulamazsa zaten 401 fırlatacak zaten
    user = get_user(fake_users_db, form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 2. Kullanıcının girdiği şifre ile veritabanındaki hash'lenmiş şifreyi karşılaştır.

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 3. Şifre doğruysa, token oluşturmak için gereken süreyi belirle.
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # 4. Kullanıcı adını içeren yeni bir access token oluştur.
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    # 5. Token'ı ve token tipini döndür.
    return {"access_token": access_token, "token_type": "bearer"}