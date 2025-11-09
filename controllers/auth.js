const jwt = require('jsonwebtoken')
const argon2 = require('argon2')
const User = require('../models/user').model

exports.login_post = async (req, res) => {
  const { email, password, type } = req.body

  User.findOne({ email, type })
    .lean()
    .then(async user => {
      if (user) {
        // Verify the password against the hash
        const isValid = await argon2.verify(user.password, password)

        if (!isValid) {
          return res.send({
            status: false
          })
        }

        // Create a token
        const payload = { user }
        const options = {
          expiresIn: process.env.JWT_EXPIRES,
          issuer: process.env.JWT_ISSUER
        }
        const secret = process.env.JWT_SECRET
        const token = jwt.sign(payload, secret, options)

        return res.send({
          status: true,
          token,
          user
        })
      } else {
        return res.send({
          status: false
        })
      }
    })
    .catch(err => {
      console.error(err)
      return res.status(500).send({ err })
    })
}

exports.login_status_get = (req, res) => {
  res.send({ success: true })
}
