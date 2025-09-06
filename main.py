# 1. FastAPI sınıfını fastapi kütüphanesinden içeri aktar (import et).
from fastapi import FastAPI

# 2. FastAPI uygulamasından bir "örnek" (instance) oluştur.
#    Bu 'app' nesnesi, API'mizin ana etkileşim noktası olacak.
app = FastAPI()


# 3. Bir "path operation decorator" tanımla.
#    @app.get("/") -> FastAPI'ye, hemen altındaki fonksiyonun
#    HTTP GET metodu ile "/" yoluna (path) gelen istekleri yöneteceğini söyler.
@app.get("/")
def read_root():
    return {"Hello": "World"}


# 4. Path parameter ile yeni bir endpoint tanımla.
#    URL'deki {item_id} kısmı, aşağıdaki fonksiyonun item_id parametresine atanacak.
@app.get("/items/{item_id}")
def read_item(item_id: int):
    # FastAPI, gelen item_id'nin bir integer olmasını zorunlu kılar.
    # Eğer "abc" gibi bir string gelirse, otomatik olarak 422 Unprocessable Entity hatası döner.
    return {"item_id": item_id}