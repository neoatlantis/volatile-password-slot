(function(){
//////////////////////////////////////////////////////////////////////////////

const AWS = require("aws-sdk");
const DYNAMODB_TABLE = process.env.VPG_DYNAMODB_TABLE;

const ddb = new AWS.DynamoDB();


async function read(key){
    const params = {
        TableName: DYNAMODB_TABLE,
        Key: {
            'uuid': { S: key }
        },
    };
    return new Promise(function(resolve, reject){
        ddb.getItem(params, function(err, data) {
            if(err) return reject(err);
            if(data && data.Item && data.Item.uuid){
                return resolve(data.Item.value.S);
            } else {
                return resolve(null);
            }
        })
    });
}


async function write(key, value){
    const params = {
        TableName: DYNAMODB_TABLE,
        Item: {
            'uuid': { S: key },
            'value': { S: value },
        },
    };
    return new Promise(function(resolve, reject){
        ddb.putItem(params, function(err, data) {
            if(err) return reject(err);
            return resolve(data);
        })
    });
}

const VolatilePasswords = require("./volatile-passwords")({
    read: read,
    write: write,
});


exports.handler = async (event) => {
    if(!DYNAMODB_TABLE){
        return {
            statusCode: 500,
            body: "Cannot find DynamoDB table. Set environment variable [VPG_DYNAMODB_TABLE] to tell me."
        }
    };

    if(!(event.uuid && event.password && event.salt)){
        return {
            statusCode: 400,
            body: "Invalid request body.",
        }
    }

    try{
        const output = await VolatilePasswords(
            event.uuid,
            event.password,
            event.salt,
        );
        return {
            statusCode: 200,
            password: output,
        };
    } catch(e){
        return {
            statusCode: 500,
            body: e.toString(),
        }
    }

};

//////////////////////////////////////////////////////////////////////////////
})();

