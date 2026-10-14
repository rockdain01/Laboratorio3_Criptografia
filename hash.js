async function pbkdf2(password, salt, iterations, keyLenBits = 256) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    typeof password === "string" ? enc.encode(password) : password,
    { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: typeof salt === "string" ? enc.encode(salt) : salt,
      iterations, hash: "SHA-256" },
    keyMaterial, keyLenBits
  );
  return new Uint8Array(bits);
}

async function bitwardenHash(password, email, iterations = 600000) {
  const masterKey = await pbkdf2(password, email.toLowerCase(), iterations);
  const hash = await pbkdf2(masterKey, password, 1);
  return btoa(String.fromCharCode(...hash));
}

bitwardenHash("<contraseña>", "benjamin.soto4@mail.udp.cl").then(console.log);