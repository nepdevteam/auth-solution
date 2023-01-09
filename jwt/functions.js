const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;

const defaultExp = Math.floor(Date.now() / 1000) + (60 * 60);

/**
 * Generates the token
 * @param {object} payload The token payload
 * @param {number} exp The timestamp in miliseconds
 */
const _generateToken = (payload, exp = defaultExp) => {
    const token = jwt.sign({
        exp,
        ...payload,
    }, secret);
    return token;
};

/**
 * Extracts the token from the request object  
 * Then validates the extracted tocken
 * @param {object} req The express request object
 */
const _tokenHeaderExtractor = function (req) {
    const token = req.headers.authorization;

    if (!token) return null;
    if (token.indexOf("JWT ") !== 0) return null;

    return token.substring('JWT '.length);
};

/**
 * Decodes the token
 * @param {string} encodedJWT The encoded token
 */
const _decode = (encodedJWT) => {
    try {
        var decodedToken = jwt.verify(encodedJWT, secret);
        return decodedToken;
    } catch (err) {
        console.log(err);
        return null;
    }
};

module.exports = {
    _generateToken,
    _tokenHeaderExtractor,
    _decode
}