const JwtStrategy = require('passport-jwt').Strategy // handles json webtoken
const ExtractJwt = require('passport-jwt').ExtractJwt
const mongoose = require('mongoose')
const User = require('../models/User')
const keys = require('./keys')

const options = {}
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.secretOrKey = keys.secretOrKey
module.exports = passport => {
    passport.use(new JwtStrategy(options, (jwt_payload, done) => {
        User.findOne({ _id: jwt_payload.id } , function(err, user) {
            if (user) {
                return done(null, user)
            } 
        })
        // console.log(jwt_payload);
    }))
}
