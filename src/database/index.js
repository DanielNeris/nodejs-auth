const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/nodeauth', { useMongoClient: true });
mongoose.Promise = global.Promise;

module.exports = mongoose;