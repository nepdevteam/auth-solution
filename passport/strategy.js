const passport = require("passport");
const { ExtractJwt, Strategy } = require("passport-jwt");

class AuthenticationPassport {
    constructor(options) {
        this.Strategy = Strategy;
        this.passport = passport;
        this.opts = {
            secretOrKey: options.secretOrKey,
            jwtFromRequest: options.tokenHeaderExtractor ? ExtractJwt.fromExtractors([options.tokenHeaderExtractor]) : ExtractJwt.fromAuthHeader,
            algorithms: ["HS256", "HS384"],
            ...options
        }

        this._configTokenBaseStrategy();
    }

    _configTokenBaseStrategy() {
        passport.use(new this.Strategy(this.opts, async function (jwt_payload, done) {
            try {
                const user = await getUserById(jwt_payload.sub);
                if (user) {
                    return done(null, user);
                } else {
                    return done(null, false);
                }
            } catch (error) {
                if (error.status === 404) {
                    error.message = "User unauthenticated";
                    error.status = 401;
                }
                return done(error, false);
            }
        }));
    }

    authenticationChecker = this.passport.authenticate('jwt', { session: false })
}

module.exports = { AuthenticationPassport };