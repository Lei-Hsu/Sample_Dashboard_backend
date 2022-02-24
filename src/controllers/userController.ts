import { Request, Response } from 'express';

import { ErrorHandler } from '../../utilities/errorHandling';

const asyncHandler = require('express-async-handler')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const User = require("../models/User");

const generateToken = (id: string) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  })
}

const singIn = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body
  try {

    if (!email || !password) {
      ErrorHandler(res, 'Please Enter Your Account Information', 401)
    }

    const userExists = await User.findOne({ email })

    if (userExists) {
      ErrorHandler(res, 'User Exists', 401)
    }

    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(password, salt)

    const userData = await User.create({
      email,
      password: hashPassword,
    })

    if (userData) {
      res.status(201).json({
        status: 'success',
        data: userData
      })
    }

  } catch (error: any) {
    ErrorHandler(res, error.message)
  }
})

const findUser = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body
  try {
    const userData = await User.findOne({ email })
    if (userData) {
      res.status(400)
      res.json({
        message: 'success',
        data: userData
      })
    } else {
      ErrorHandler(res, 'Can not find the user', 401)
    }
  } catch (error: any) {
    ErrorHandler(res, error.message)
  }
})

const logIn = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body

  try {
    const user = await User.findOne({ email })

    if (!user) ErrorHandler(res, 'Email is not correct', 401)

    if (user && await bcrypt.compare(password, user.password)) {
      res.status(200)
      res.json({
        status: 'success',
        data: {
          _id: user.id,
          email: user.email,
          JWTToken: generateToken(user.id)
        }
      })
    } else {
      ErrorHandler(res, 'Password is not correct', 401)
    }
  } catch (error: any) {
    ErrorHandler(res, error.message)
  }
})

const check = asyncHandler(async (req: Request, res: Response) => {
  const userProfile = req.body
  res.status(200)
  res.json({
    status: 'success',
    data: {
      _id: userProfile.id,
      email: userProfile.email,
    }
  })
})

module.exports = {
  singIn,
  findUser,
  logIn,
  check
};
