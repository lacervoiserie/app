const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let VilleSchema = new Schema({
    position: Number,
    ville: String,
    avater: String,
    image: String,
    favoris: String,
    plu: String,
});

// Export the model
module.exports = mongoose.model('Villes', VilleSchema);