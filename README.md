# APIyer Proxy

Cloudflare Worker untuk meneruskan request HTTP ke beberapa backend melalui Cloudflare Quick Tunnel yang URL-nya dapat berubah.

## Alur

Backend berjalan dan memulai Quick Tunnel. Backend mendaftarkan URL tunnel dengan nama rute. Pengguna memanggil domain Worker melalui /p/nama-backend/path. Worker meneruskan method, query, header yang relevan, dan body ke backend terdaftar.

## Setup

1. Jalankan: npx wrangler kv namespace create ROUTES
2. Masukkan ID KV hasil perintah ke wrangler.toml menggantikan REPLACE_WITH_KV_NAMESPACE_ID.
3. Pasang secret: npx wrangler secret put PROXY_API_KEY
4. Jalankan npm install, npm run check, lalu npm run deploy.

Jangan gunakan secret contoh untuk produksi. Ubah ALLOWED_ORIGIN pada wrangler.toml ke origin aplikasi yang benar-benar digunakan.

## Register backend

POST /api/register dengan header X-API-Key berisi secret pendaftaran, Content-Type application/json, dan JSON:
{"backend":"zvid-api","Url":"https://id-tunnel-acak.trycloudflare.com"}

Field backend menentukan nama rute. Url menerima URL HTTPS trycloudflare.com. Field payload opsional menjadi body default untuk POST, PUT, atau PATCH jika pemanggil tidak menyertakan body. Body dari pemanggil akan diprioritaskan. Field clientKey opsional mengunci akses pemanggil, dan nilainya harus minimal 16 karakter.

Format kompatibilitas juga menerima nama berisi secret pendaftaran pada body, tetapi penggunaan header X-API-Key lebih disarankan.

## Memanggil backend

Gunakan URL Worker /p/zvid-api/v1/generate untuk mengakses path /v1/generate pada backend. Tambahkan header X-Proxy-Client-Key apabila backend didaftarkan dengan clientKey.

Satu Worker bisa memiliki banyak rute. Pendaftaran berlaku satu jam; backend sebaiknya memperbarui rute setiap 25-30 menit dan segera mendaftar ulang saat URL tunnel berubah. GET /api/routes menampilkan daftar nama rute dan GET /health memeriksa konfigurasi. POST /api/unregister menghapus rute dengan JSON {"backend":"zvid-api"}.

## Batasan

Upstream hanya diizinkan pada HTTPS dengan hostname trycloudflare.com yang valid. Domain arbitrer dan URL dengan kredensial, query, atau fragment ditolak. Worker tidak dapat menjaga Quick Tunnel tetap hidup jika proses tunnel berhenti. Atur clientKey pada setiap rute yang tidak boleh diakses publik.

## Contoh registrasi otomatis

Setelah tunnel aktif, atur environment berikut pada proses backend:

~~~sh
export PROXY_URL="https://<worker-domain>"
export PROXY_API_KEY="<secret-yang-dipasang-di-worker>"
export BACKEND_NAME="zvid-api"
export TRYCF_URL="https://id-tunnel-acak.trycloudflare.com"
export REGISTER_LOOP="1"
node examples/register.mjs
~~~

Script mendaftarkan rute saat mulai dan memperbaruinya setiap 25 menit. Jalankan script di proses yang tetap hidup selama tunnel aktif. Jika URL tunnel berubah, perbarui TRYCF_URL dan jalankan ulang script. Untuk mencoba request melalui proxy, gunakan examples/proxy-request.mjs dengan PROXY_URL, BACKEND_NAME, BACKEND_PATH, HTTP_METHOD, dan REQUEST_BODY_JSON sesuai kebutuhan.

Contoh JSON yang cocok dengan bentuk request awal:
~~~json
{
  "nama": "ISI_DENGAN_PROXY_API_KEY",
  "backend": "zvid-api",
  "Url": "https://id-tunnel-acak.trycloudflare.com",
  "payload": {"prompt": "test"}
}
~~~
Dalam format ini, nama berisi nilai secret pendaftaran. Untuk produksi, lebih disarankan memindahkan nilai secret ke header X-API-Key dan tidak menyertakannya dalam JSON. Jalankan juga npm test untuk menguji routing dan autentikasi secara lokal setelah npm install.
