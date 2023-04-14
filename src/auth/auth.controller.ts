import { GetCurrentUser, GetCurrentUserId } from './common/decorators';
import { AtGuard } from './common/guards/at.guard';
import { RtGuard } from './common/guards/rt.guard';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(dto);
  }
  @HttpCode(HttpStatus.OK)
  @Post('local/signin')
  signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(dto);
  }

  @UseGuards(AtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
