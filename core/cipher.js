(function(){
//////////////////////////////////////////////////////////////////////////////


const crypto = require("crypto");

const IV_LENGTH = 16;
const DATA_LENGTH = 128;

const HMAC_ALGO = "sha256";
const HMAC_LENGTH = 16;

const CIPHERTEXT_LENGTH = IV_LENGTH + HMAC_LENGTH + DATA_LENGTH;
const CIPHER_ALGO = "aes-256-ctr";

const SCRYPT_N = 1048576;
const SCRYPT_r = 8;
const SCRYPT_p = 1;
const SCRYPT_maxmem = 4 * 1024 * 1024 * 1024;




async function randomBytes(n){
    return new Promise(function(resolve, reject){
        crypto.randomBytes(n, function(error, buf){
            if(error) return reject(error);
            resolve(buf);
        });
    });
}

async function deriveKey(password, salt, len){
    return new Promise(function(resolve, reject){
        crypto.scrypt(
            password,
            salt,
            len,
            { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p, maxmem: SCRYPT_maxmem },
            function(err, d){
                if(err) return reject(err);
                resolve(d);
            }
        );
    });
}

function HMAC(buffer, key){
    const hmacCalc = crypto.createHmac(HMAC_ALGO, key);
    hmacCalc.update(buffer);
    return hmacCalc.digest().slice(0, HMAC_LENGTH);
}


async function encrypt(buffer, key){
    const IV = await randomBytes(IV_LENGTH);
    const encipher = crypto.createCipheriv(CIPHER_ALGO, key, IV);
    const hmacTag = HMAC(buffer, key);

    var output = encipher.update(buffer);
    output = Buffer.concat([output, encipher.final()]);

    return Buffer.concat([IV, hmacTag, output]);
}

async function decrypt(buffer, key){
    if(!buffer || buffer.length < IV_LENGTH + HMAC_LENGTH){
        return null;
    }
    const IV = buffer.slice(0, IV_LENGTH);
    const hmacTag = buffer.slice(IV_LENGTH, IV_LENGTH + HMAC_LENGTH);
    const ciphertext = buffer.slice(IV_LENGTH + HMAC_LENGTH);
    const decipher = crypto.createDecipheriv(CIPHER_ALGO, key, IV);

    var plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);

    const actualHmacTag = HMAC(plaintext, key);
    
    if(actualHmacTag.toString("hex") != hmacTag.toString("hex")) return null;
    return plaintext;
}




module.exports.allocateBuffer = function(){
    return Buffer.alloc(CIPHERTEXT_LENGTH);
}

module.exports.rotate = async function rotate(buffer, password, salt){
    /* 
    Decrypt and re-encrypt storage. Then returns the decrypted secret.
    If storage cannot be decrypted, clear it with a new secret.

    This assures the storage retains the same secret if a given password is
    entered repeatedly. Otherwise, one wrong password will cause the secret be
    permanently erased.
    */

    if(!buffer || buffer.length != CIPHERTEXT_LENGTH){
        throw Error("Requires a buffer with " + CIPHERTEXT_LENGTH + " bytes.");
    }


    var createNew = false;

    const algo = "aes-256-ctr";
    const key = await deriveKey(password, salt, 32);

    const voidSecret = await randomBytes(DATA_LENGTH);

    var secret = await decrypt(buffer, key);
  
    if(null === secret){
        // kill the secret buffer, update with new random bytes
        secret = voidSecret;
    }


    const newBuffer = await encrypt(secret, key);

    if(newBuffer.length != buffer.length) {
        throw Error("Buffer length mismatch.");
    }

    for(var i=0; i<buffer.length; i++){
        buffer[i] = newBuffer[i];
    }


    return secret;
}




/*async function test(){
    const genericBuffer = Buffer.alloc(CIPHERTEXT_LENGTH);
    
    const password1 = Buffer.from("password1");
    const password2 = Buffer.from("password2");


    console.log("secret", await module.exports.rotate(
        genericBuffer,
        password1,
        "salt"
    ));
    
    console.log("buffer", genericBuffer, genericBuffer.length);

    console.log("secret", await module.exports.rotate(
        genericBuffer,
        password1,
        "salt"
    ));
    
    console.log("buffer", genericBuffer, genericBuffer.length);

    console.log("secret", await module.exports.rotate(
        genericBuffer,
        password2,
        "salt"
    ));
    
    console.log("buffer", genericBuffer, genericBuffer.length);

    console.log("secret", await module.exports.rotate(
        genericBuffer,
        password2,
        "salt"
    ));
    
    console.log("buffer", genericBuffer, genericBuffer.length);

}
test();*/



//////////////////////////////////////////////////////////////////////////////
})();
