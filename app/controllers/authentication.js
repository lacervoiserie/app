var jwt = require('jsonwebtoken'); 
var User = require('../models/user');
var authConfig = require('../../config/auth');
var bcrypt   = require('bcrypt-nodejs');
 
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
            passport: passport
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

exports.forgot_password = function(req, res) {
    var email = req.body.email;

    User.findOne({email: email}, function(err, existingUser){
 
        if(err){
            return res.json({ message: 'erreur' });
        }

        if(existingUser){

            var userInfo = setUserInfo(existingUser);
            var token = 'JWT_' + generateToken(userInfo);

            User.findOneAndUpdate({_id: userInfo._id},{ $set: { reset_password_token: token, reset_password_expires: Date.now() + 86400000 }}, function(err2, existingUser2){
                console.log(existingUser2);
            });
            
            var nodemailer = require('nodemailer');
            var smtpTransport = nodemailer.createTransport({
              service: 'gmail',
              auth: {
                user: 'lacervoiserie17000@gmail.com',
                pass: 'Boiteacom17!'
              }
            });

            var data = {
                to: email,
                from: 'lacervoiserie17000@gmail.com',
                subject: 'La Cervoiserie - Mot de passe oublié',
                html: '<!DOCTYPE html><html><head><title>La Cervoiserie - Mot de passe oublié</title></head><body><div><h3>Bonjour,</h3><p>Vous avez demandé une réinitialisation de votre mot de passe, merci de l’utiliser <a href="http://pizza-re.com/LC?token='+token+'">ce lien</a> pour réinitialiser votre mot de passe.</p><br><p>La Cervoiserie</p></div></body></html>'
            };

            smtpTransport.sendMail(data, function(err) {
                if (!err) {
                   console.log('ok');
                  return res.json({ message: 'ok' });
                } else {
                   console.log('probleme');
                  return res.json({ message: 'probleme' });
                }
            });
            
        }else{
            return res.json({ message: 'non' });
        }
 
    });

  /*async.waterfall([
    function(done) {
      User.findOne({
        email: req.body.email
      }).exec(function(err, user) {
        if (user) {
          done(err, user);
        } else {
          done('User not found.');
        }
      });
    },
    function(user, done) {
      // create the random token
      crypto.randomBytes(20, function(err, buffer) {
        var token = buffer.toString('hex');
        done(err, user, token);
      });
    },
    function(user, token, done) {
      User.findByIdAndUpdate({ _id: user._id }, { reset_password_token: token, reset_password_expires: Date.now() + 86400000 }, { upsert: true, new: true }).exec(function(err, new_user) {
        done(err, token, new_user);
      });
    },
    function(token, user, done) {
      var data = {
        to: user.email,
        from: email,
        template: '<!DOCTYPE html><html><head><title>Forget Password Email1</title></head><body><div><h3>Dear {{name}},</h3><p>You requested for a password reset, kindly use this <a href="{{url}}">link</a> to reset your password</p><br><p>Cheers!</p></div></body></html>',
        subject: 'Password help has arrived!',
        context: {
          url: 'http://localhost:3000/auth/reset_password?token=' + token,
          name: user.fullName.split(' ')[0]
        }
      };

      smtpTransport.sendMail(data, function(err) {
        if (!err) {
          return res.json({ message: 'Kindly check your email for further instructions' });
        } else {
          return done(err);
        }
      });
    }
  ], function(err) {
    return res.status(422).json({ message: err });
  });*/
};

exports.reset_password = function(req, res, next) {

    console.log(req.body.newPassword);

    if(req.body.newPassword){
                console.log("newPassword");

        User.findOne({ reset_password_token: req.body.token, reset_password_expires: { $gt: Date.now() } }, function(err, existingUser){
            
                console.log("findOne");
            if(err){
                return res.json({ message: 'erreur' });
            }

            if(existingUser){
                var userInfo = setUserInfo(existingUser);
                console.log("userInfo");
                console.log(userInfo);

                var SALT_FACTOR = 5;
                var user_tempo;
             
                bcrypt.genSalt(SALT_FACTOR, function(err, salt){
             
                    if(err){
                        return next(err);
                    }
             
                    bcrypt.hash(req.body.newPassword, salt, null, function(err, hash){
             
                        if(err){
                            return next(err);
                        }
             
                        user_tempo = hash;

                        console.log(user_tempo);
                        User.findOneAndUpdate({reset_password_token: req.body.token},{ $set: { reset_password_token: "undefined", reset_password_expires: "undefined", password: user_tempo }}, function(err2, existingUser2){
                            console.log(existingUser2);
                        });
             
                    });
             
                });

                /*var user = new User({
                    email: userInfo.email,
                    pseudo: userInfo.pseudo,
                    password: req.body.newPassword,
                    role: userInfo.role,
                    reset_password_token: "undefined", 
                    reset_password_expires: "undefined"
                });
         
                user.save(function(err, user){
         
                    if(err){
                        return next(err);
                    }else{
                        console.log("okkkk");
                    }
         
                    var userInfo = setUserInfo(user);
         
                    res.status(201).json({
                        token: 'JWT ' + generateToken(userInfo),
                        user: userInfo
                    })
         
                });*/

            }

            /*if (!err && user) {
              
                user.password = req.body.newPassword;
                user.reset_password_token = undefined;
                user.reset_password_expires = undefined;
                user.save(function(err, user) {
                  if (err) {
                    return res.status(422).send({
                      message: err
                    });
                  } else {
            
                    var nodemailer = require('nodemailer');
                    var smtpTransport = nodemailer.createTransport({
                      service: 'gmail',
                      auth: {
                        user: 'lacervoiserie17000@gmail.com',
                        pass: 'Boiteacom17!'
                      }
                    });

                    var data = {
                      to: user.email,
                      from: 'lacervoiserie17000@gmail.com',
                      subject: 'La Cervoiserie - Confirmation de réinitialisation du mot de passe',
                      html: '<!DOCTYPE html><html><head><title>La Cervoiserie - Confirmation de réinitialisation du mot de passe</title></head><body><div><h3>Bonjour,</h3><p>Votre mot de passe a été réinitialisé avec succès, vous pouvez maintenant vous connecter avec votre nouveau mot de passe.</p><br><div>A bientôt!</div></div></body></html>'
                    };

                    smtpTransport.sendMail(data, function(err) {
                      if (!err) {
                        return res.json({ message: 'Votre mot de passe a été réinitialisé avec succès, vous pouvez maintenant vous connecter avec votre nouveau mot de passe.' });
                      } else {
                        return done(err);
                      }
                    });
                  }
                });
            } else {
              return res.status(400).send({
                message: 'Le jeton de réinitialisation du mot de passe est invalide ou a expiré.'
              });
            }*/
          });
        
        return res.status(400).send("Félicitation, votre mot de passe à été réinitialisé avec succès!");
    }else{
        return res.status(404).send("Désolé, veuillez entre un nouveau mot de passe...");
    }



    /*User.findOne({reset_password_token: req.body.token,reset_password_expires: {$gt: Date.now()}},function(err, user) {
        if (!err && user) {
            console.log(user);
            if (req.body.newPassword === req.body.verifyPassword) {
                console.log('verifyPassword');
            }
        }
    });*/

    /*
  User.findOne({
    reset_password_token: req.body.token,
    reset_password_expires: {
      $gt: Date.now()
    }
  }).exec(function(err, user) {
    if (!err && user) {
      if (req.body.newPassword === req.body.verifyPassword) {
        user.hash_password = bcrypt.hashSync(req.body.newPassword, 10);
        user.reset_password_token = undefined;
        user.reset_password_expires = undefined;
        user.save(function(err) {
          if (err) {
            return res.status(422).send({
              message: err
            });
          } else {
            var data = {
              to: user.email,
              from: email,
              subject: 'Password Reset Confirmation2',
              html: '<!DOCTYPE html><html><head><title>Password Reset2</title></head><body><div><h3>Dear {{name}},</h3><p>Your password has been successful reset, you can now login with your new password.</p><br><div>Cheers!</div></div></body></html>'
            };

            smtpTransport.sendMail(data, function(err) {
              if (!err) {
                return res.json({ message: 'Password reset' });
              } else {
                return done(err);
              }
            });
          }
        });
      } else {
        return res.status(422).send({
          message: 'Passwords do not match'
        });
      }
    } else {
      return res.status(400).send({
        message: 'Password reset token is invalid or has expired.'
      });
    }
  });*/
};