'use strict';

const Initializer = require('@and1gio/z-app-core').Initializer;

const mongoose = require('mongoose');
const passport = require('passport');
const BearerStrategy = require('passport-http-bearer').Strategy;
const jwt = require('jsonwebtoken');

class SessionInitializer extends Initializer {

    constructor(app) {
        super(app);
    }

    async init() {
        try {
            /**
             * schema
             */
            const SessionSchema = mongoose.Schema({
                token: { type: String, required: true, unique: true },
                userAgent: { type: String },
                data: { type: mongoose.Schema.Types.Mixed, required: true },
                createdAt: { type: Date, default: Date.now },
                expiresAt: { type: Date, expires: 1, required: true }
            });

            /**
             * connection
             */
            const connection = await mongoose.createConnection(this.app.configs.session.store.url);
            this.app.logger.info('### connected to session db ###');

            /**
             * model
             */
            const Session = connection.model('Session', SessionSchema);

            /**
             * setup passportjs
             */
            passport.use(new BearerStrategy((accessToken, done) => {
                const expires = new Date(Date.now() + (this.app.configs.session.store.ttl || 3600000));

                const findQuery = { token: accessToken };
                const updateQuery = {
                    $set: { expiresAt: expires }
                }

                Session.findOneAndUpdate(findQuery, updateQuery, { new: true }, (err, record) => {
                    if (err) { return done(err); }
                    if (!record) { return done(null, false); }

                    if (this.app.configs.session.showLogs) {
                        console.log(record);
                    }

                    return done(null, record, { scope: 'all' });
                });
            }));

            /**
             * session
             */
            this.app.session = {
                /**
                 * @param {*} userData
                 * @param {*} payload
                 * @param {*} expiresAt
                 */
                create: (userData, payload, expiresAt, userAgent) => {
                    return new Promise((resolve, reject) => {
                        const expires = expiresAt || (new Date(Date.now() + (this.app.configs.session.store.ttl || 3600000)));
                        const token = jwt.sign(payload, this.app.configs.session.secret);
                        const session = new Session({
                            userAgent: userAgent,
                            data: userData,
                            token: token,
                            createdAt: Date.now(),
                            expiresAt: expires
                        });

                        session.save((error) => {
                            if (error) {
                                reject({ status: 500, errors: this.app.utils.generateError('middleware', 'session', 'client', null, 'session_save_error') });
                            }
                            resolve(session);
                        });
                    });
                },

                check: passport.authenticate('bearer', { session: false }),

                /**
                 * @param {*} token
                 */
                destroy: (token) => {
                    return new Promise((resolve, reject) => {
                        Session.deleteOne({ token: token }, (error) => {
                            if (error) {
                                reject({ status: 500, errors: this.app.utils.generateError('middleware', 'session', 'client', null, 'session_delete_error') });
                            }
                            resolve(true);
                        });
                    });
                }
            };
        } catch (error) {
            throw error;
        }
    }
}

module.exports = SessionInitializer;