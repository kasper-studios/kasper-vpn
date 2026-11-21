//! Встроенный MTProto-прокси — отдельная опция для Telegram.
//!
//! Протокол повторяет эталонную реализацию alexbers/mtprotoproxy (прямое
//! подключение к датацентрам Telegram, fast mode), поэтому настоящие клиенты
//! Telegram подключаются по ссылке tg://proxy?server=…&port=…&secret=….
//! Исходящий трафик к датацентрам идёт через локальный вход sing-box, то есть
//! через VLESS-туннель пользователя.

use aes::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use uuid::Uuid;

type AesCtr = ctr::Ctr128BE<aes::Aes256>;

const TG_DATACENTER_PORT: u16 = 443;
const TG_DATACENTERS_V4: [Ipv4Addr; 5] = [
    Ipv4Addr::new(149, 154, 175, 50),
    Ipv4Addr::new(149, 154, 167, 51),
    Ipv4Addr::new(149, 154, 175, 100),
    Ipv4Addr::new(149, 154, 167, 91),
    Ipv4Addr::new(149, 154, 171, 5),
];

const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const HANDSHAKE_LEN: usize = 64;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;
const MATERIAL_LEN: usize = KEY_LEN + IV_LEN;

const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef; 4];
const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
const PROTO_TAG_SECURE: [u8; 4] = [0xdd; 4];

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BUF_SIZE: usize = 16 * 1024;
const REPLAY_CACHE_LEN: usize = 8192;

type Nonce = [u8; MATERIAL_LEN];

/// Разобранное рукопожатие клиента. Шифры продолжают счётчик с места,
/// на котором он остановился после рукопожатия, — как в эталоне.
pub struct ClientHandshake {
    pub proto_tag: [u8; 4],
    /// Индекс датацентра в том виде, в каком его прислал клиент (1-based, знаковый).
    pub dc_index: i16,
    /// Расшифровка client → proxy (счётчик уже на 64 байтах).
    decryptor: AesCtr,
    /// Ключевой материал proxy → client; встраивается в рукопожатие к датацентру.
    enc_key_and_iv: [u8; MATERIAL_LEN],
    /// handshake[8..56] — идентификатор для защиты от повтора.
    pub nonce: Nonce,
}

fn ctr(key: &[u8], iv: &[u8]) -> AesCtr {
    AesCtr::new_from_slices(key, iv).expect("ключ 32 байта и iv 16 байт")
}

fn reverse_material(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// Разбор первых 64 байт соединения. `Err(())` — неподходящий тег протокола
/// или неверный секрет: соединение просто закрывается.
pub fn parse_handshake(secret: &[u8; 16], handshake: &[u8; HANDSHAKE_LEN]) -> Result<ClientHandshake, ()> {
    let dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + MATERIAL_LEN];
    let dec_key = Sha256::digest([dec_prekey, secret].concat());

    let reversed = reverse_material(&handshake[SKIP_LEN..SKIP_LEN + MATERIAL_LEN]);
    let enc_key = Sha256::digest([&reversed[..PREKEY_LEN], secret].concat());

    let mut decryptor = ctr(&dec_key, dec_iv);
    let mut decrypted = *handshake;
    decryptor.apply_keystream(&mut decrypted);

    let proto_tag: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]
        .try_into()
        .unwrap();
    if !matches!(
        proto_tag,
        PROTO_TAG_ABRIDGED | PROTO_TAG_INTERMEDIATE | PROTO_TAG_SECURE
    ) {
        return Err(());
    }
    let dc_index = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);

    let mut enc_key_and_iv = [0u8; MATERIAL_LEN];
    enc_key_and_iv[..KEY_LEN].copy_from_slice(&enc_key);
    enc_key_and_iv[KEY_LEN..].copy_from_slice(&reversed[PREKEY_LEN..]);

    Ok(ClientHandshake {
        proto_tag,
        dc_index,
        decryptor,
        enc_key_and_iv,
        nonce: handshake[SKIP_LEN..SKIP_LEN + MATERIAL_LEN]
            .try_into()
            .unwrap(),
    })
}

fn random_bytes() -> [u8; HANDSHAKE_LEN] {
    // Зарезервированные начала нонса: по ним трафик отличают от HTTP/других
    // транспортов MTProto. Совпадения перегенерируем.
    const RESERVED: [[u8; 4]; 6] = [
        *b"HEAD",
        *b"POST",
        *b"GET ",
        PROTO_TAG_INTERMEDIATE,
        PROTO_TAG_SECURE,
        [0x16, 0x03, 0x01, 0x02],
    ];
    loop {
        let mut rnd = [0u8; HANDSHAKE_LEN];
        for chunk in rnd.chunks_mut(16) {
            chunk.copy_from_slice(&Uuid::new_v4().into_bytes());
        }
        if rnd[0] == 0xef || rnd[4..8] == [0; 4] || RESERVED.iter().any(|r| rnd[..4] == *r) {
            continue;
        }
        return rnd;
    }
}

/// Рукопожатие к датацентру: случайный нонс, в который встроен (в перевёрнутом
/// виде) ключевой материал клиента, тег протокола и зашифрованный хвост.
/// Возвращает байты для отправки и шифр proxy → датацентр (счётчик на 64).
fn dc_handshake(proto_tag: &[u8; 4], enc_key_and_iv: &[u8; MATERIAL_LEN]) -> ([u8; HANDSHAKE_LEN], AesCtr) {
    let mut rnd = random_bytes();
    rnd[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(proto_tag);
    rnd[SKIP_LEN..SKIP_LEN + MATERIAL_LEN].copy_from_slice(&reverse_material(enc_key_and_iv));

    let key: [u8; KEY_LEN] = rnd[SKIP_LEN..SKIP_LEN + KEY_LEN].try_into().unwrap();
    let iv: [u8; IV_LEN] = rnd[SKIP_LEN + KEY_LEN..SKIP_LEN + MATERIAL_LEN]
        .try_into()
        .unwrap();

    // Эталон шифрует весь нонс целиком и берёт хвост: счётчик уходит на 64.
    let mut wire = rnd;
    ctr(&key, &iv).apply_keystream(&mut wire);
    wire[..PROTO_TAG_POS].copy_from_slice(&rnd[..PROTO_TAG_POS]);
    (wire, ctr(&key, &iv))
}

/// Подключение к датацентру напрямую или через SOCKS5 (наш sing-box вход).
async fn connect_upstream(
    upstream: Option<&(String, u16)>,
    addr: IpAddr,
    port: u16,
) -> io::Result<TcpStream> {
    let Some((host, socks_port)) = upstream else {
        return TcpStream::connect((addr, port)).await;
    };
    let mut stream = TcpStream::connect((host.as_str(), *socks_port)).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other("SOCKS5-сервер не поддерживает подключение без аутентификации"));
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match addr {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(io::Error::other("SOCKS5 отклонил подключение к датацентру"));
    }
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5: неизвестный тип адреса {other}"
            )));
        }
    }
    Ok(stream)
}

async fn handle_client(
    mut client: TcpStream,
    secret: [u8; 16],
    upstream: Option<(String, u16)>,
    replay: &Mutex<HashSet<Nonce>>,
) {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    match timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut handshake)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let parsed = match parse_handshake(&secret, &handshake) {
        Ok(parsed) => parsed,
        Err(()) => return,
    };
    if let Ok(mut replay) = replay.lock() {
        // При переполнении просто сбрасываем: защита от повтора — эвристика.
        if replay.len() >= REPLAY_CACHE_LEN {
            replay.clear();
        }
        if !replay.insert(parsed.nonce) {
            return;
        }
    }

    let dc_index = parsed.dc_index.unsigned_abs() as usize;
    let Some(dc) = TG_DATACENTERS_V4.get(dc_index.saturating_sub(1)) else {
        return;
    };
    let (wire, dc_encryptor) = dc_handshake(&parsed.proto_tag, &parsed.enc_key_and_iv);
    let mut tg = match timeout(
        CONNECT_TIMEOUT,
        connect_upstream(upstream.as_ref(), IpAddr::V4(*dc), TG_DATACENTER_PORT),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return,
    };
    if tg.write_all(&wire).await.is_err() {
        return;
    }

    let (mut client_read, mut client_write) = client.into_split();
    let (mut tg_read, mut tg_write) = tg.into_split();
    let mut decryptor = parsed.decryptor;
    let mut encryptor = dc_encryptor;

    let up = tokio::spawn(async move {
        let mut buf = [0u8; BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    decryptor.apply_keystream(&mut buf[..n]);
                    encryptor.apply_keystream(&mut buf[..n]);
                    if tg_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Fast mode: датацентр шифрует тем же ключом, которого ждёт клиент, поэтому
    // обратное направление проксируется байт-в-байт без криптографии.
    let down = tokio::spawn(async move {
        let mut buf = [0u8; BUF_SIZE];
        loop {
            match tg_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::select! {
        _ = up => (),
        _ = down => (),
    }
}

/// Точка входа сервера: работает до отмены задачи.
pub async fn run(
    listener: TcpListener,
    secret: [u8; 16],
    upstream: Option<(String, u16)>,
) -> io::Result<()> {
    let replay = Arc::new(Mutex::new(HashSet::new()));
    loop {
        let (client, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => continue,
            Err(error) => return Err(error),
        };
        let replay = Arc::clone(&replay);
        let upstream = upstream.clone();
        tokio::spawn(async move {
            handle_client(client, secret, upstream, &replay).await;
        });
    }
}

pub fn generate_secret() -> String {
    hex(&Uuid::new_v4().into_bytes())
}

pub fn parse_secret(secret: &str) -> Option<[u8; 16]> {
    let secret = secret.trim();
    if secret.len() != 32 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&secret[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn proxy_link(host: &str, port: u16, secret_hex: &str) -> String {
    format!("tg://proxy?server={host}&port={port}&secret={secret_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Клиент, как его видит сервер: рукопожатие + шифры для потока после него.
    fn simulate_client(
        secret: &[u8; 16],
        proto_tag: [u8; 4],
        dc_index: i16,
    ) -> ([u8; HANDSHAKE_LEN], AesCtr, AesCtr) {
        let mut handshake = random_bytes();
        handshake[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag);
        handshake[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_index.to_le_bytes());

        let dec_key = Sha256::digest([
            &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
            secret,
        ]
        .concat());
        let reversed = reverse_material(&handshake[SKIP_LEN..SKIP_LEN + MATERIAL_LEN]);
        let enc_key = Sha256::digest([&reversed[..PREKEY_LEN], secret].concat());

        // Настоящий клиент шифрует весь нонс (счётчик уходит на 64) и отправляет
        // первые 56 байт открытым текстом — так же расшифровывает и сервер.
        let mut outgoing = ctr(
            &dec_key,
            &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + MATERIAL_LEN],
        );
        let mut wire = handshake;
        outgoing.apply_keystream(&mut wire);
        wire[..PROTO_TAG_POS].copy_from_slice(&handshake[..PROTO_TAG_POS]);
        let incoming = ctr(&enc_key, &reversed[PREKEY_LEN..]);
        (wire, outgoing, incoming)
    }

    #[test]
    fn parses_handshake_and_continues_client_stream() {
        let secret = parse_secret(&generate_secret()).unwrap();
        let (wire, mut client_outgoing, _) = simulate_client(&secret, PROTO_TAG_ABRIDGED, 2);
        let parsed = parse_handshake(&secret, &wire).unwrap();
        assert_eq!(parsed.proto_tag, PROTO_TAG_ABRIDGED);
        assert_eq!(parsed.dc_index, 2);

        let mut decryptor = parsed.decryptor;
        let mut payload = *b"payload after handshake";
        client_outgoing.apply_keystream(&mut payload);
        decryptor.apply_keystream(&mut payload);
        assert_eq!(&payload, b"payload after handshake");
    }

    #[test]
    fn rejects_wrong_secret_and_unknown_tag() {
        let secret = parse_secret(&generate_secret()).unwrap();
        let other = parse_secret(&generate_secret()).unwrap();
        let (wire, _, _) = simulate_client(&secret, PROTO_TAG_ABRIDGED, 1);
        assert!(parse_handshake(&other, &wire).is_err());
        let (wire, _, _) = simulate_client(&secret, [0x01, 0x02, 0x03, 0x04], 1);
        assert!(parse_handshake(&secret, &wire).is_err());
    }

    #[test]
    fn dc_handshake_embeds_reversed_client_material() {
        let material = [0xaa; MATERIAL_LEN];
        let (wire, mut dc_cipher) = dc_handshake(&PROTO_TAG_ABRIDGED, &material);
        // Первые 56 байт — открытые и содержат перевёрнутый материал клиента.
        assert_eq!(&wire[SKIP_LEN..SKIP_LEN + MATERIAL_LEN], reverse_material(&material).as_slice());
        // Тег в хвосте зашифрован, счётчик шифра уже на 64.
        assert_ne!(&wire[PROTO_TAG_POS..PROTO_TAG_POS + 4], &PROTO_TAG_ABRIDGED);
        let mut probe = *b"probe bytes";
        dc_cipher.apply_keystream(&mut probe);
        assert_ne!(&probe, b"probe bytes");
    }

    #[test]
    fn secret_and_link_helpers_roundtrip() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32);
        let parsed = parse_secret(&secret).unwrap();
        assert_eq!(hex(&parsed), secret);
        assert!(parse_secret("zz").is_none());
        assert!(parse_secret(&secret[..31]).is_none());
        assert_eq!(
            proxy_link("127.0.0.1", 17893, &secret),
            format!("tg://proxy?server=127.0.0.1&port=17893&secret={secret}")
        );
    }

    /// Мини-сервер SOCKS5 без аутентификации, пропускающий трафик в обе стороны.
    async fn fake_socks(listener: TcpListener, target: (std::net::Ipv4Addr, u16)) {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut head = [0u8; 10];
        client.read_exact(&mut head).await.unwrap();
        client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await.unwrap();
        let mut upstream = TcpStream::connect((IpAddr::V4(target.0), target.1)).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }

    #[tokio::test]
    async fn socks5_upstream_connects_and_relays() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut data = [0u8; 5];
            socket.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping!");
            socket.write_all(b"pong!").await.unwrap();
        });

        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        let socks_task = tokio::spawn(fake_socks(socks, (Ipv4Addr::LOCALHOST, echo_port)));

        let upstream = (String::from("127.0.0.1"), socks_port);
        let mut stream = connect_upstream(Some(&upstream), IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
            .await
            .unwrap();
        stream.write_all(b"ping!").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");
        echo_task.await.unwrap();
        socks_task.abort();
    }

    #[tokio::test]
    async fn server_end_to_end_through_fake_dc() {
        // Полный цикл fast mode: клиент ↔ MTProto-сервер ↔ SOCKS5 ↔ «датацентр».
        let secret = parse_secret(&generate_secret()).unwrap();

        let dc = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc_port = dc.local_addr().unwrap().port();
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();

        let socks_task = tokio::spawn(fake_socks(socks, (Ipv4Addr::LOCALHOST, dc_port)));
        let server = tokio::spawn(run(
            proxy,
            secret,
            Some((String::from("127.0.0.1"), socks_port)),
        ));

        let (wire, mut client_outgoing, mut client_incoming) =
            simulate_client(&secret, PROTO_TAG_ABRIDGED, 1);
        let mut socket = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        socket.write_all(&wire).await.unwrap();
        let mut payload = *b"request-to-dc";
        client_outgoing.apply_keystream(&mut payload);
        socket.write_all(&payload).await.unwrap();

        // Датацентр расшифровывает запрос ключом из полученного рукопожатия.
        let (mut dc_socket, _) = dc.accept().await.unwrap();
        let mut dc_wire = [0u8; HANDSHAKE_LEN];
        dc_socket.read_exact(&mut dc_wire).await.unwrap();
        // Тег протокола на проводе зашифрован — проверяем через одноразовый шифр.
        let mut probe = dc_wire;
        ctr(&dc_wire[SKIP_LEN..SKIP_LEN + KEY_LEN], &dc_wire[SKIP_LEN + KEY_LEN..SKIP_LEN + MATERIAL_LEN])
            .apply_keystream(&mut probe);
        assert_eq!(&probe[PROTO_TAG_POS..PROTO_TAG_POS + 4], &PROTO_TAG_ABRIDGED);

        let mut dc_incoming = ctr(
            &dc_wire[SKIP_LEN..SKIP_LEN + KEY_LEN],
            &dc_wire[SKIP_LEN + KEY_LEN..SKIP_LEN + MATERIAL_LEN],
        );
        let mut request = [0u8; 13];
        dc_socket.read_exact(&mut request).await.unwrap();
        dc_incoming.apply_keystream(&mut request);
        assert_eq!(&request, b"request-to-dc");

        // Ответ датацентра клиент получает байт-в-байт и расшифровывает своим
        // входящим шифром — проверка трюка fast mode. Датацентр переворачивает
        // весь 48-байтовый блок целиком и делит на ключ (32) и iv (16).
        let whole = reverse_material(&dc_wire[SKIP_LEN..SKIP_LEN + MATERIAL_LEN]);
        let mut dc_outgoing = ctr(&whole[..KEY_LEN], &whole[KEY_LEN..]);
        let mut response = *b"response";
        dc_outgoing.apply_keystream(&mut response);
        dc_socket.write_all(&response).await.unwrap();

        let mut got = [0u8; 8];
        socket.read_exact(&mut got).await.unwrap();
        client_incoming.apply_keystream(&mut got);
        assert_eq!(&got, b"response");

        server.abort();
        socks_task.abort();
    }
}
