window.onload = load_defaults_values

const BASEURL = "http://localhost:9000";

function load_defaults_values() {
    let nip5id = document.getElementById("nostr-id");
    nip5id.value = "the_name_is_bob_bob_smith@frogs.cloud";

    let privateKeyElement = document.getElementById("nostr-private-key");

    privateKeyElement.value = "nsec1rlpycvsa8xuyuqumsdgcssengqc65j87fnmwpffkv7a2tgj3gc0sltukmh";

    let examplePin = document.getElementById("pin");
    examplePin.value = 132432

    let examplePassword = document.getElementById("password");
    examplePassword.value = "stack_sats_and_pet_cats";

}


async function send_key() {
    console.log("upload_key");
    const privateKeyElement = document.getElementById("nostr-private-key");
    const privateKey = privateKeyElement.value;

    const pinRaw = document.getElementById("pin");
    const pin = Number(pinRaw.value);

    const examplePassword = document.getElementById("password");
    const password = examplePassword.value;

    const exmapleNip5id = document.getElementById("nostr-id");
    const nip5id = exmapleNip5id.value;

    if (!(pin && password && privateKey)) {
        console.log("missing required values");
        return
    }
    const encryptedKey = await encryptData(privateKey, password);
    console.log(encryptedKey);
    const res = await upload_key(BASEURL, pin, encryptedKey, nip5id);
    console.log(res);
}

async function get_key() {
    console.log("fetch_key");
    const pinRaw = document.getElementById("pin");
    const pin = Number(pinRaw.value);
    const exmapleNip5id = document.getElementById("nostr-id");
    const nip5id = exmapleNip5id.value;
    const res = await fetch_key(BASEURL, pin, nip5id);
    console.log(res);
    const examplePassword = document.getElementById("password");
    const password = examplePassword.value;
    decryptData(res.private_key_hash, password)
}

async function encryptData(privateKey, password) {
    // Convert the password to a Uint8Array
    const passwordUint8Array = new TextEncoder().encode(password);

    // Generate a 256-bit random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const iterations = 100000;
    const length = 256;

    // Derive a 256-bit key from the password and salt using PBKDF2
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        passwordUint8Array,
        "PBKDF2",
        false, ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey({
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: "SHA-256"
        },
        passwordKey, {
            name: "AES-GCM",
            length: length
        },
        true, // Can be used for encryption
        ["encrypt"] // Can be used for encryption
    );

    // Convert the plaintext to a Uint8Array
    const plaintext = new TextEncoder().encode(privateKey);

    // Generate a 12-byte random initialization vector (IV)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the plaintext using the key and IV
    const ciphertext = await window.crypto.subtle.encrypt({
                name: "AES-GCM",
                iv: iv,
            },
            key,
            plaintext
        )
        // Convert the salt, IV, and ciphertext to Base64 strings
    const saltBase64 = window.btoa(String.fromCharCode(...salt));
    const ivBase64 = window.btoa(String.fromCharCode(...iv));
    const ciphertextBase64 = window.btoa(String.fromCharCode(...new Uint8Array(ciphertext)));

    console.log(`Salt: ${saltBase64}`);
    console.log(`IV: ${ivBase64}`);
    console.log(`Ciphertext: ${ciphertextBase64}`);
    const combined = `$PBKDF2$i=${iterations},l=${length},s=${saltBase64}$AESGM$${ivBase64}$${ciphertextBase64}`;
    console.log(`Combined: ${combined}`);
    const encrypted = document.getElementById("encrypted");
    encrypted.innerHTML = combined;
    return combined;
}

const replacer = (key, value) => {
    if (typeof value === 'number') {
        return value;
    }
    return value;
};

async function upload_key(baseUrl, pin, encryptedKey, nip5) {
    return fetch(`${baseUrl}/upload_key`, {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            nip_05_id: nip5,
            pin: pin,
            private_key_hash: encryptedKey,
        }, replacer)
    });
}

async function fetch_key(baseUrl, pin, nip5) {
    response = await fetch(`${baseUrl}/fetch_key`, {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            nip_05_id: nip5,
            pin: pin,
        }, replacer)
    });
    return response.json();
}

async function decryptData(encryptedData, password) {
    //  const combined = `$PBKDF2$i=${iterations},l=${length},s=${saltBase64}$AESGM$${ivBase64}$${ciphertextBase64}`;
    parts = encryptedData.split("$");
    console.log(parts);
    const hashFunctionName = parts[1];
    const iterations = parts[2].split(",")[0].split("=")[1];
    const length = parts[2].split(",")[1].split("=")[1];
    const saltBase64 = parts[2].split(",")[2].split("=")[1];
    const ivBase64 = parts[4];
    const ciphertextBase64 = parts[5];

    // Convert the password to a Uint8Array
    const passwordUint8Array = new TextEncoder().encode(password);

    // Convert the salt, IV, and ciphertext from Base64 strings to Uint8Arrays
    const salt = new Uint8Array(Array.from(atob(saltBase64), c => c.charCodeAt(0)));
    const iv = new Uint8Array(Array.from(atob(ivBase64), c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array(Array.from(atob(ciphertextBase64), c => c.charCodeAt(0)));

    // Derive the key from the password and salt using PBKDF2
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        passwordUint8Array,
        hashFunctionName,
        false, ["deriveKey"]
    )

    const key = await window.crypto.subtle.deriveKey({
            name: hashFunctionName,
            salt: salt,
            iterations: iterations,
            hash: "SHA-256"
        },
        passwordKey, {
            name: "AES-GCM",
            length: length
        },
        true, // Can be used for decryption
        ["decrypt"] // Can be used for decryption
    );

    // Decrypt the ciphertext using the key and IV
    const plaintext = await window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv,
        },
        key,
        ciphertext
    )

    // Convert the plaintext to a string and log it to the console
    const plaintextString = new TextDecoder().decode(plaintext);
    console.log(`Plaintext: ${plaintextString}`);

    let decryptedPrivateKeyElement = document.getElementById("nostr-private-key-decrypted");
    decryptedPrivateKeyElement.value = plaintextString;
    let privateKeyElement = document.getElementById("nostr-private-key");

    let matchedElement = document.getElementById("matched");
    matchedElement.checked = plaintextString === privateKeyElement.value;
    return plaintextString;
}