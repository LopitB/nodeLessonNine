import { userService } from '../services/userService';
import { Request, Response } from "express";

import { COOKIE } from '../constants/cookie';
import { IUser } from '../entity/user';
import { IRequestExtended } from '../interfaces';
import { authService, tokenService } from "../services";
import { tokenRepository } from '../repositories/token/tokenRepository';

class AuthController {
  public async registration(req: Request, res: Response) {
    try {
      const data = await authService.registration(req.body);
      res.cookie(
        'refreshToken',
        data?.refreshToken,
        { maxAge: COOKIE.maxAgeRefreshToken, httpOnly: true } // httpOnly for security (will not allow malicious JS code)
      );

      return res.json(data);
    } catch (e: any) {
      console.log(e);
    }
  }

  public async logout(req: IRequestExtended, res: Response): Promise<Response<string>> {
    const { id } = req.user as IUser; // user may noy be found

    await tokenService.deleteUserTokenPair(id);

    return res.json('Ok');
  }

  public async login(req: IRequestExtended, res: Response) {
    try {
      const { id, email, password: hashPassword } = req.user as IUser; // from middleware
      const { password } = req.body; // extract password from input to check if it matches

      await userService.compareUserPasswords(password, hashPassword);

      const { refreshToken, accessToken } = tokenService.generateTokenPair({ userId: id, userEmail: email });

      // save in DB
      await tokenRepository.createToken({
        refreshToken,
        accessToken,
        userId: id
      })

      // returned to frontend as response
      res.json({
        refreshToken,
        accessToken,
        user: req.user,
      });
    } catch (e) {
      res.status(400).json(e);
    }
  }

  public async refresh(req: IRequestExtended, res: Response) {
    try {
      const { id, email } = req.user as IUser; // from middleware
      const refreshTokenToDelete = req.get('Authorization');

      await tokenService.deleteTokenPairByParams({ refreshToken: refreshTokenToDelete }); // deleted old token pair with this token

      const { refreshToken, accessToken } = tokenService.generateTokenPair({ userId: id, userEmail: email }); // generated new token pair

      await tokenRepository.createToken({ refreshToken, accessToken, userId: id }); // saved in DB

      // returned to frontend as response
      res.json({
        refreshToken,
        accessToken,
        user: req.user,
      })

    } catch (e) {
      res.status(400).json(e);
    }
  }
}

export const authController = new AuthController();
