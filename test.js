/*
Demonstrative usage of core.

*/

(async function(){
//////////////////////////////////////////////////////////////////////////////

const datastore = {
    '8fba4998-8f12-4e0f-b561-2c5d5e71e497': 'Kx+Hi6qkBCFpnIXwoVxOjG81oH0oFZaoKCktOFL9Esy1S6Q6Ycq9mrizYOcjNy8eDaMPqs8lyqQdtRKHvAidCTs95mLprV7kskuhfPIQoFUjXKXbyRPJjI10tvhp+qeVkQ/LX9jA4hh5UZREWrhN7bMo1ao8ZeuDKcA7E6zyw7sO/8708oCFlZhfs8Jj77Ch6hIRIsVIGTjS7HhtZfjFDA=='
};

const VolatilePasswords = require("./volatile-passwords")({
    read: async function(key){
        return datastore[key];
    },
    write: async function(key, value){
        datastore[key] = value;
    },
});

const UUID = "8fba4998-8f12-4e0f-b561-2c5d5e71e497";
const password1 = "password1";
const password2 = "password2";

const salt1 = "salt1";
const salt2 = "salt2";



console.log("password1");
console.log(await VolatilePasswords(UUID, password1, salt1));

console.log("password1");
console.log(await VolatilePasswords(UUID, password1, salt1));

console.log("password2");
console.log(await VolatilePasswords(UUID, password2, salt1));

console.log("password1");
console.log(await VolatilePasswords(UUID, password1, salt1));








//////////////////////////////////////////////////////////////////////////////
})();
