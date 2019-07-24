const Villes = require('../models/villes.model');


exports.villes = function (req, res) {

    Villes.find( function (err, villes) {
        if (err) return (err);
        res.json(villes);
    })
};

exports.ville = function (req, res) {

    Villes.findById(req.params.id, function (err, villes) {
        if (err) return (err);
        res.send(villes);
    })
};

exports.villes_create = function (req, res) {
    let villes = new Villes(
        {
            position: req.body.position,
            ville: req.body.ville,
            avatar: req.body.avatar,
            image: req.body.image,
            favoris: req.body.favoris,
            plu: req.body.plu,
        }
    );

    villes.save(function (err) {
        if (err) {
            return (err);
        }
        res.send('Ville Created successfully')
    })
};

