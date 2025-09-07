# models.py

from pydantic import BaseModel
from typing import Optional
# Kullanıcı başarıyla giriş yaptığında (/login endpoint'i), ona geri döndüreceğimiz JWT token'ının yapısını tanımlar. 
# Bu modele göre, yanıtımız her zaman bir access_token ve bir token_type (genellikle "bearer") alanı içermelidir.
class Token(BaseModel):
    access_token: str
    token_type: str
#Bu model, bir JWT token'ının içinde sakladığımız verinin yapısını temsil eder. create_access_token fonksiyonu, kullanıcı adını bu modelin yapısına uygun bir şekilde token'ın "payload" kısmına gömer. 
#Daha sonra, korumalı bir endpoint'e istek geldiğinde, token'ı çözüp içinden kullanıcı adını güvenli bir şekilde okumak için bu modeli kullanırız.
class TokenData(BaseModel):
    username: Optional[str] = None
#Bir kullanıcı hakkındaki temel, herkese açık bilgileri temsil eder. 
#Örneğin, bir kullanıcının profilini döndürürken bu modeli kullanabiliriz. 
#Şifre gibi hassas bilgileri içermez.
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
#Bu sınıf, User sınıfından miras alır (inheritance). 
# Yani User sınıfının tüm alanlarına (username, email vb.) sahiptir ve ek olarak hashed_password alanını içerir. 
# Adından da anlaşılacağı gibi, bu model veritabanında sakladığımız tam kullanıcı verisini temsil eder. 
# Bir kullanıcıyı veritabanından çekerken veya veritabanına kaydederken bu modeli kullanırız.

class UserInDB(User):
    hashed_password: str