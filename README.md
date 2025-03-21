# Proje Kurulumu ve Bağımlılıkların Yüklenmesi

Bu rehber, projeyi başka bir ortamda çalıştırmak isteyen kullanıcılar için bağımlılıkların nasıl yükleneceğini adım adım açıklamaktadır.

## Projeyi Klonlama

Öncelikle, projeyi GitHub veya başka bir kaynaktan yerel makinenize klonlayın:

```bash
git clone <proje_linki>
cd <proje_dizini>
```

## Sanal Ortam Oluşturma

Projeyi izole bir ortamda çalıştırmak için bir sanal ortam oluşturmanız önerilir. Aşağıdaki komutu çalıştırarak sanal ortamı oluşturabilirsiniz:

```bash
python -m venv venv
```

## Sanal Ortamı Aktifleştirme

Sanal ortamı aktifleştirmek için işletim sisteminize uygun komutu kullanın:

### Windows:
```bash
venv\Scripts\activate
```

### Mac/Linux:
```bash
source venv/bin/activate
```

## Bağımlılıkları Yükleme

Bağımlılıkları yüklemek için aşağıdaki komutu çalıştırın:

```bash
pip install -r requirements.txt
```

Bu komut, proje için gerekli olan tüm bağımlılıkları `requirements.txt` dosyasından okuyarak yükleyecektir.

## Projeyi Çalıştırma

Bağımlılıkları yükledikten sonra, projenizi başlatmak için ilgili komutu çalıştırabilirsiniz. Örneğin:

```bash
python main.py
```

## Sanal Ortamı Devre Dışı Bırakma

Çalışmanızı tamamladıktan sonra sanal ortamı devre dışı bırakmak için:

```bash
deactivate
```

## Sorun Giderme

Eğer bağımlılıkları yüklerken hata alırsanız, aşağıdaki adımları deneyin:

- `pip` sürümünü güncelleyin:
  ```bash
  python -m pip install --upgrade pip
  ```
- `requirements.txt` dosyanızın doğru konumda olduğundan emin olun.
- Sanal ortamın aktif olduğundan emin olun.

---

Bu adımları takip ederek projeyi başarılı bir şekilde kurabilir ve çalıştırabilirsiniz. İyi çalışmalar!

