export class RegisterUserReqest {
  username: string;
  password: string;
  name: string;
}
export class UserResponse {
  username: string;
  name: string;
  token?: string;
}
export class LoginResponse {
  username: string;
  password: string;
}
export class UpdateUserRequest {
  name?: string;
  password?: string;
}
