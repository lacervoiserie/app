const express = require('express');
const router = express.Router();

// Require the controllers WHICH WE DID NOT CREATE YET!!
const villes_controller = require('../controllers/villes.controller');
const product_controller = require('../controllers/product.controller');

router.get ('/villes', villes_controller.villes);
router.get ('/ville/:id', villes_controller.villes);
router.post ('/villes/create', villes_controller.villes_create);

// a simple test url to check that all of our files are communicating correctly.
router.get('/test', product_controller.test);
router.post ('/create', product_controller.product_create);
router.get ('/:id', product_controller.product_details);
router.put ('/:id/update', product_controller.product_update);
router.delete ('/:id/delete', product_controller.product_delete);


module.exports = router;