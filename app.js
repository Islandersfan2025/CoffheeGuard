// Client-side password-based AES-GCM decryption that reveals the URL if the password is correct.
// The encrypted payload below was produced with:
// - PBKDF2(HMAC-SHA-256), iterations=200000, keyLen=32 bytes
// - AES-GCM (12 byte IV), tag length 128 bits
//
// Note: the encrypted values (salt, iv, ct, tag) are base64 strings.
// The real secret (plaintext URL) will be recovered only if the supplied passphrase derives the correct key.

(async () => {
  // Encrypted payload (precomputed)
  const payload = {
    salt: "SusiR23OK4/sutxYc8EZ1g==",
    iv:   "X+6jhGH+WJvUW/Va",
    ct:   "Fqoh9nSr/1bmRjL3U+BsXOBrN1IPfH/IwxGXrI9ZTWp2SDfQ6KqCcxXXmJdj5bH84+vMa2Dz5kf9KnEBVWXaayJ0IA==",
    tag:  "lNVH8ePk2HXGI2TialHJ0Q=="
  };

  // Helper: base64 -> ArrayBuffer
  function b64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  // Derive CryptoKey using PBKDF2 (SHA-256)
  async function deriveKeyFromPassword(password, saltBase64, iterations = 200000) {
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    const saltBuf = b64ToArrayBuffer(saltBase64);
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuf,
        iterations: iterations,
        hash: "SHA-256"
      },
      passKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    return derivedKey;
  }

  // AES-GCM decrypt: ciphertext (ct) + tag must be concatenated for WebCrypto
  async function decryptAesGcm(derivedKey, ivBase64, ctBase64, tagBase64) {
    const iv = new Uint8Array(b64ToArrayBuffer(ivBase64));
    const ct = new Uint8Array(b64ToArrayBuffer(ctBase64));
    const tag = new Uint8Array(b64ToArrayBuffer(tagBase64));

    // Concatenate ct || tag
    const cipherWithTag = new Uint8Array(ct.length + tag.length);
    cipherWithTag.set(ct, 0);
    cipherWithTag.set(tag, ct.length);

    try {
      const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        derivedKey,
        cipherWithTag.buffer
      );
      const dec = new TextDecoder();
      return dec.decode(plainBuf);
    } catch (e) {
      // Decryption failed (wrong key or corrupted data)
      throw new Error("Decryption failed — invalid key.");
    }
  }

  // UI wiring
  const keyInput = document.getElementById("accessKey");
  const btn = document.getElementById("checkBtn");
  const msg = document.getElementById("msg");
  const result = document.getElementById("result");
  const exchangeLink = document.getElementById("exchangeLink");
  const copyBtn = document.getElementById("copyBtn");

  btn.addEventListener("click", async () => {
    msg.textContent = "";
    result.style.display = "none";

    const pass = keyInput.value || "";
    if (!pass) {
      msg.textContent = "Please enter the access key.";
      return;
    }

    try {
      // Derive key and attempt decrypt
      const derivedKey = await deriveKeyFromPassword(pass, payload.salt, 200000);
      const url = await decryptAesGcm(derivedKey, payload.iv, payload.ct, payload.tag);

      // Success!
      exchangeLink.href = url;
      exchangeLink.textContent = url;
      result.style.display = "block";
      msg.textContent = "";
    } catch (err) {
      msg.textContent = "Invalid access key.";
      console.debug(err);
    }
  });

  copyBtn.addEventListener("click", () => {
    const url = exchangeLink.href;
    if (!url) return;
    navigator.clipboard?.writeText(url).then(() => {
      copyBtn.textContent = "Copied!";
      setTimeout(()=> copyBtn.textContent = "Copy URL", 1200);
    }).catch(()=> {
      copyBtn.textContent = "Copy failed";
      setTimeout(()=> copyBtn.textContent = "Copy URL", 1200);
    });
  });
})();
