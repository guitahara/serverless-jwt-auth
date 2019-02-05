const mongoose = require("mongoose");
const config = require('config');

let isConnected;

module.exports = connectToDatabase = () => {
    const connectionString = config.get('db');
    if (isConnected) {
        console.log('=> using existing database connection');
        return Promise.resolve();
    }

    console.log('=> using new database connection');
    return mongoose.connect(connectionString)
        .then(db => {
            isConnected = db.connections[0].readyState;
        });
};