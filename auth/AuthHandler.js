const connectToDatabase = require('../db');
const User = require('../user/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs-then');
const config = require('config');
const secret = config.get('secret');

module.exports.register = (event, context) => {
    context.callbackWatisForEmptyEventLoop = false;

    return connectToDatabase()
        .then(() => register(JSON.parse(event.body)))
        .then(session => ({
            statusCode: 200,
            body: JSON.stringify(session)
        }))
        .catch(err => ({
            statusCode: err.StatusCode || 500,
            headers: { 'Content-Type': 'text/plain' },
            body: err.message
        }));
};

module.exports.login = (event, context) => {
    context.callbackWatisForEmptyEventLoop = false;

    return connectToDatabase()
        .then(() => 
            login(JSON.parse(event.body))
        )
        .then(session => ({
            statusCode: 200,
            body: JSON.stringify(session)
        }))
        .catch(err => ({
            statusCode: err.statusCode || 500,
            headers: { 'Content-Type': 'text/plain' },
            body: { stack: err.stack, message: err.message }
        }));
};

module.exports.me = (event, context) => {
    context.callbackWatisForEmptyEventLoop = false;

    return connectToDatabase()
        .then(() => 
            me(event.requestContext.authorizer.principalId)
        )
        .then(session => ({
            statusCode: 200,
            body: JSON.stringify(session)
        }))
        .catch(err => ({
            statusCode: err.statusCode || 500,
            headers: { 'Content-Type': 'text/plain' },
            body: { stack: err.stack, message: err.message }
        }));
};

function me(userId) {
    return User.findById(userId, { password: 0})
        .then(user => 
            !user
            ? Promise.reject('No user found.')
            : user
        )
        .catch(err => Promise.reject(new Error(err)));
}

function login(eventBody) {
    return User.findOne({ email: eventBody.email })
        .then(user => 
            !user
            ? Promise.reject(new Error('User with that email does not exists.'))
            : comparePassword(eventBody.password, user.password, user._id)
        )
        .then(token => ({ auth: true, token: token }))
}

function comparePassword(eventPassword, userPassword, userId) {
    return bcrypt.compare(eventPassword, userPassword)
        .then(passwordIsValid => 
            !passwordIsValid
            ? Promise.reject(new Error('the credentials do not match.'))
            : signToken(userId)
        );
}

function signToken(id) {
    return jwt.sign({ id: id }, secret , {
        expiresIn: 86400 //expires in 24 hours
    });
}

function checkIfInputIsValid(eventBody) {
    if (
        !(eventBody.password && eventBody.password.length >= 7)
    ) {
        return Promise.reject(new Error('Password error. Password needs to be longer than 8 characters.'));
    }

    if (
        !(eventBody.name &&
          eventBody.name.length > 5 &&
          typeof eventBody.name === 'string')
    ) return Promise.reject(new Error('Username error. Username needs to be longer than 5 characters.'));

    if (
        !(eventBody.email &&
          typeof eventBody.name === 'string')
    ) return Promise.reject(new Error('Email error. Email must have valid characters.'));

    return Promise.resolve();
}

function register(eventBody) {
    return checkIfInputIsValid(eventBody)
        .then(() => 
            User.findOne({ email: eventBody.email })
        )
        .then( user => 
            user
            ? Promise.reject(new Error('User with that email exists.'))
            : bcrypt.hash(eventBody.password, 8)
        )
        .then(hash => 
            User.create({ name: eventBody.name, email: eventBody.email, password: hash })
        )
        .then( user => ({ auth: true, token: signToken(user._id) }));
};