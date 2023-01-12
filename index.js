const jwt = require("./jwt/functions");
const { AuthenticationPassport } = require("./passport/strategy");

module.exports = Object.assign({}, { jwt, AuthenticationPassport });