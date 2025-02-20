import { Body, Controller, Get, HttpCode, Patch, Post } from '@nestjs/common';
import {
  RegisterUserReqest,
  UserResponse,
  LoginResponse,
  UpdateUserRequest,
} from '../model/user.model';
import { WebResponse } from '../model/web.model';
import { UserService } from './user.service';
import { User } from '@prisma/client';
import { Auth } from '../common/auth.decorator';

@Controller('/api/users')
export class UserController {
  constructor(private userService: UserService) {}

  @Post()
  @HttpCode(200)
  async register(
    @Body() request: RegisterUserReqest,
  ): Promise<WebResponse<UserResponse>> {
    const result = await this.userService.register(request);
    return {
      data: result,
    };
  }
  @Post('/login')
  @HttpCode(200)
  async login(
    @Body() request: LoginResponse,
  ): Promise<WebResponse<UserResponse>> {
    const result = await this.userService.login(request);
    return {
      data: result,
    };
  }

  @Get('/current')
  @HttpCode(200)
  async get(@Auth() user: User): Promise<WebResponse<UserResponse>> {
    const result = await this.userService.get(user);

    return {
      data: result,
    };
  }

  @Patch('/current')
  @HttpCode(200)
  async update(
    @Auth() user: User,
    @Body() request: UpdateUserRequest,
  ): Promise<WebResponse<UserResponse>> {
    const result = await this.userService.updateUser(user, request);
    return {
      data: result,
    };
  }
}
