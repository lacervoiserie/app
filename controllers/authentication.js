var jwt = require('jsonwebtoken'); 
var User = require('../models/user');
var authConfig = require('../../config/auth');
 
function generateToken(user){
    return jwt.sign(user, authConfig.secret, {
        expiresIn: 10080
    });
}
 
function setUserInfo(request){
    return {
        _id: request._id,
        pseudo: request.pseudo,
        email: request.email,
        role: request.role,
        passport: request.passport
    };
}
 
exports.login = function(req, res, next){
 
    var userInfo = setUserInfo(req.user);
 
    res.status(200).json({
        token: 'JWT ' + generateToken(userInfo),
        user: userInfo
    });
 
}
 
exports.register = function(req, res, next){
 
    var email = req.body.email;
    var pseudo = req.body.pseudo;
    var password = req.body.password;
    var role = req.body.role;
    var passport = req.body.passport;
 
    if(!email){
        return 'You must enter an email address';
    }

    if(!pseudo){
        return 'You must enter an pseudo';
    }
 
    if(!password){
        return 'You must enter a password';
    }
 
    User.findOne({email: email}, function(err, existingUser){
 
        if(err){
            return next(err);
        }
 
        if(existingUser){
            return 'That email address is already in use';
        }
 
        var user = new User({
            email: email,
            pseudo: pseudo,
            password: password,
            role: role,
            passport: passport,
            reset_password_token: 'undefined',
            reset_password_expires: 'undefined',
        });
 
        user.save(function(err, user){
 
            if(err){
                return next(err);
            }
 
            var userInfo = setUserInfo(user);
 
            res.status(201).json({
                token: 'JWT ' + generateToken(userInfo),
                user: userInfo
            })
 
        });
 
    });
 
}
 
exports.roleAuthorization = function(roles){
 
    return function(req, res, next){
 
        var user = req.user;
 
        User.findById(user._id, function(err, foundUser){
 
            if(err){
                res.status(422).json({error: 'No user found.'});
                return next(err);
            }
 
            if(roles.indexOf(foundUser.role) > -1){
                return next();
            }
 
            res.status(401).json({error: 'You are not authorized to view this content'});
            return next('Unauthorized');
 
        });
 
    }
 
}