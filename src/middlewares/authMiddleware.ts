import { tokenRepository } from '../repositories/token/tokenRepository';
import { IRequestExtended } from '../interfaces';
import { userService } from '../services';
import { NextFunction, Response } from 'express';
import { tokenService } from '../services';
import { variables } from '../constants';

class AuthMiddleware {
  public async checkAccessToken(req: IRequestExtended, res: Response, next: NextFunction) {
    try {
      const accessToken  = req.get(variables.AUTHORIZATION);

      if (!accessToken) {
        throw new Error('Token is invalid!');
      }

      const { userEmail } = tokenService.verifyToken(accessToken);

//   tokenService.verifyToken(authToken) = {
//    userId: 7,
//    userEmail: 'Marlboro3@mail.com',
//    iat: 1648212421, // created
//    exp: 1648298821 // expires
//   }

      const tokenPairFromDB = await tokenRepository.findByParams({ accessToken });

      if (!tokenPairFromDB) {
        throw new Error('Token is invalid!')
      }

      const userFromToken = await userService.getUserByEmail(userEmail);

      if (!userFromToken) {
        throw new Error('Wrong token');
      }

      req.user = userFromToken; // extended request (object)

      next();
    } catch (error: any) {
      res.status(401)
        .json({
        status: 401,
        message: error.message,
        tokenValue: req.get(variables.AUTHORIZATION)
      })
    }
  }

  public async checkRefreshToken(req: IRequestExtended, res: Response, next: NextFunction) {
    try {
      const refreshToken  = req.get(variables.AUTHORIZATION);

      if (!refreshToken) {
        throw new Error('Token is invalid!');
      }

      const { userEmail } = tokenService.verifyToken(refreshToken, 'refresh');

//   tokenService.verifyToken(authToken) = {
//    userId: 7,
//    userEmail: 'Marlboro3@mail.com',
//    iat: 1648212421, // created
//    exp: 1648298821 // expires
//   }

      // search if token exists in DB
      const tokenPairFromDB = await tokenRepository.findByParams({ refreshToken });

      if (!tokenPairFromDB) {
        throw new Error('Token is invalid!')
      }

      const userFromToken = await userService.getUserByEmail(userEmail);

      if (!userFromToken) {
        throw new Error('Wrong token');
      }

      req.user = userFromToken; // extended request (object); transfer user next
      next();

    } catch (error: any) {
      res.status(401)
        .json({
        status: 401,
        message: error.message,
        tokenValue: req.get(variables.AUTHORIZATION)
      })
    }
  }
}

export const authMiddleware = new AuthMiddleware();
