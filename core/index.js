(function(){
//////////////////////////////////////////////////////////////////////////////
/*
Core logic of Volatile Password Slot
====================================

Volatile Password Slot(s) are cloud functions running on servers, which serves
as HMAC-based password generators for multiple users. Each user authenticates
with a random slot UUID, and a password, then the slot generates a random
password with a salt as user specifies.

Behaviour of volatile password slots is, the output is constant(for same salt)
if the user types the same password at each authentication. Once a different
password is typed in, the slot is "rotated", to a new state where even if the
previous password being entered later it will not return to the previous state,
and thus the output is permanently changed. This design ensures the
authenticating party MUST have fully awareness of consequences caused by a
wrong password, technically making things like rubber hose attacks difficult
to achieve its goal.

This core script packs above logic in a single file. It is not working out of
box, and must be initialized with functions for:

    * user authentication
    * key-based storage access(read and write)

After initialization, the script returns a function which can be called by
(UUID, password, salt).
*/

const crypto = require("crypto");
const cipher = require("./cipher");
const rotate = cipher.rotate;
const allocateBuffer = cipher.allocateBuffer;




function HMAC(buffer, key){
    const hmacCalc = crypto.createHmac("sha512", key);
    hmacCalc.update(buffer);
    return hmacCalc.digest();
}


async function verifiedWriteback(readfunc, writefunc, key, value){
    /*
        Update database records and ensures the value is written back by
        doing a read afterwards.
    */

    const oldVal = await readfunc(key);
    if(oldVal === value) return; // no update necessary

    await writefunc(key, value);

    for(var i=3; i>0; i--){ // try 3 times
        const newVal = await readfunc(key);
        if(newVal != oldVal && newVal == value) return; // update okay
    }

    throw Error("Database writeback failed.");
}




async function main(_readfunc, _writefunc, UUID, password, salt){
    if(!/^[a-f0-9]{8}(\-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(UUID)){
        throw Error("Invalid UUID.");
    }
    UUID = UUID.toLowerCase();

    // Prepare our I/O functions:
    //  1. we only operate on entry key = UUID.
    //  2. `value` is automatically encoded as Base64 in database and converted
    //     to Buffer when read.

    const read = async function(){
        const val = await _readfunc(UUID);
        if(val === null) return;
        try{
            return Buffer.from(val, "base64"); 
        } catch(e){
            return;
        }
    }

    const write = async function(value){
        if(value !== null) value = value.toString("base64");
        await verifiedWriteback(_readfunc, _writefunc, UUID, value);
    }

    // Read database entry

    const buffer = allocateBuffer();

    try{
        const dbOldVal = await read();
        if(dbOldVal){
            dbOldVal.copy(buffer, 0, 0, buffer.length);
        }
    } catch(e){
        throw Error("Failed reading database.");
    }

    // Do rotation. `buffer` is updated after this. Always get a secret for
    // password generation.
    // `rotate` function requires a salt, which is different from the `salt`
    // parameter in this function call -- it's a user specific parameter, and
    // we use UUID to fill that.
    const secret = await rotate(buffer, password, UUID);

    // Writeback new buffer immediately. Only when database updates confirmed
    // can we reveal the secret!

    await write(buffer);

    // Derive a salt-specific password from secret and salt.

    const subSecret = HMAC(secret, "secret" + UUID);
    const subSalt = HMAC(salt, "salt" + UUID);
    return HMAC(subSecret, subSalt).toString("base64");

}









module.exports = function init(options){
    /* Initialization of the core logic. `options` must be like:
        {
            read: async function(key){...},
            write: async function(key, newVal){...},
        }

        Where `read` must be an asynchronous function taking a `key` string
        for input and returns the value in database or null. `write` takes
        an additional `newVal` and updates the database. If `newVal` is null,
        it shall remove the entry in database.
    */

    return async function VolatilePassword(UUID, password, salt){
        try{
            const result = await main(
                options.read, options.write,
                UUID, password, salt
            );
            return { "error": false, "password": result };
        } catch(e){
            return { "error": e.toString() };
        }
    };
};
//////////////////////////////////////////////////////////////////////////////
})();
