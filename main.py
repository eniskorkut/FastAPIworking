#FastAPI: Uygulamamızın ana sınıfı.
#Depends: FastAPI'nin "Dependency Injection" sistemini kullanmamızı sağlar. 
# OAuth2PasswordRequestForm gibi hazır bağımlılıkları fonksiyonlarımıza enjekte etmek için kullanacağız.
#HTTPException, status: Kullanıcı adı/şifre yanlış olduğunda 401 Unauthorized gibi standart HTTP hataları fırlatmak için gereklidir.
#timedelta: Token'ın geçerlilik süresini belirlemek için kullanılır.
#OAuth2PasswordRequestForm: Standart bir "kullanıcı adı ve şifre" formundan gelen veriyi yakalamak için FastAPI'nin sağladığı özel bir sınıftır.
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
# auth modülünü import ediyoruz ve modelleri de ekliyoruz.
import auth
import database
from models import Token, User


app = FastAPI() # Tüm API endpoint'lerimizi (@app.get, @app.post vb.) bu app nesnesi üzerinden tanımlayacağız.


@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Kullanıcı adı ve şifre ile giriş yaparak JWT token alır."""
    
    # 1. Kullanıcıyı bulmaya çalış. Bulunamazsa, genel bir hata ver.
    user = database.get_user(database.fake_users_db, form_data.username)
    
    # 2. Kullanıcı yoksa VEYA şifre yanlışsa, aynı güvenlik hatasını döndür.
    #    Bu, saldırganların hangi kullanıcı adlarının geçerli olduğunu anlamasını engeller.
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Şifre doğruysa, token oluşturmak için gereken süreyi belirle.
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)

    # 4. Kullanıcı adını içeren yeni bir access token oluştur.
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # 5. Token'ı ve token tipini döndür.
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(auth.get_current_active_user)):
    """Sadece geçerli token'a sahip kullanıcıların kendi bilgilerini görebileceği endpoint."""
    return current_user