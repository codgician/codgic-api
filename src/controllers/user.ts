/* /src/controllers/user.ts
   We love our users! */

import * as createError from 'http-errors';
import { Context } from 'koa';

import { checkPrivilege, UserPrivilege } from './../init/privilege';
import * as UserModel from './../models/user';

export async function getUserInfo(ctx: Context, next: () => Promise<any>) {

  if (!ctx.params.username) {
    ctx.params.username = ctx.state.user.username;
  }

  // Retrieve user info.
  const userInfo = await UserModel.getUserInfo(ctx.params.username, 'username');

  if (!userInfo) {
    throw createError(404, 'User not found.');
  }

  ctx.body = userInfo;
  ctx.status = 200;

  await next();

}

export async function searchUser(ctx: Context, next: () => Promise<any>) {

  // Validate request.
  if (!ctx.query.q) {
    throw createError('Query cannot be blank.');
  }

  if (ctx.query.sort && (ctx.query.sort !== 'id' || ctx.query.sort !== 'username' || ctx.query.sort !== 'createdAt')) {
    ctx.query.sort = undefined;
  }

  if (ctx.query.direction && (ctx.query.direction !== 'ASC' || ctx.query.direction !== 'DESC')) {
    ctx.query.direction = undefined;
  }

  let page = parseInt(ctx.query.page, 10);
  let perPage = parseInt(ctx.query.perPage, 10);

  if (page < 1) {
    page = 1;
  }
  if (perPage < 1) {
    perPage = 1;
  }

  // Retrieve search result.
  const userList = await UserModel
    .searchUser(
      ctx.query.q,
      ctx.query.sort,
      ctx.query.direction,
      page,
      perPage,
    );

  ctx.body = userList;
  ctx.status = 200;

  await next();

}

export async function postUser(ctx: Context, next: () => Promise<any>) {

  // Logged in users cannot sign up again.
  if (ctx.state.user) {
    throw createError(400, 'Please log out first.');
  }

  ctx.request.body.id = undefined;

  // Validate request.
  if (!(ctx.request.body.email && ctx.request.body.username && ctx.request.body.password)) {
    throw createError(400, 'Required fields are missing.');
  }
  await UserModel.validateUserInfo(ctx.request.body);

  // Post user.
  const userInfo = await UserModel.postUser(ctx.request.body);

  ctx.body = userInfo;
  ctx.status = 201;

  await next();

}

export async function updateUser(ctx: Context, next: () => Promise<any>) {

  // Check login.
  if (!ctx.state.user) {
    throw createError(401);
  }

  // Check if user has the privilege to modify other users.
  if (checkPrivilege(UserPrivilege.editUser, ctx.state.user.privilege)) {
    if (ctx.params.username !== ctx.state.user.username) {
      const tempUserInfo = await UserModel.getUserInfo(ctx.params.username, 'username');
      if (!tempUserInfo) {
        throw createError(400, 'User does not exist.');
      }
      ctx.request.body.id = tempUserInfo.id;
    } else {
      ctx.request.body.id = ctx.state.user.id;
    }
  } else {
    // Then you can only modify your own info.
    // And you can't modify your own privilege.
    ctx.request.body.privilege = undefined;

    if (ctx.params.username !== ctx.state.user.username) {
      throw createError(403);
    } else {
      ctx.request.body.id = ctx.state.user.id;
    }

  }

  // Validate request.
  if (ctx.method === 'POST' && !(ctx.request.body.email && ctx.request.body.username && ctx.request.body.password)) {
    throw createError(400, 'Required fields are missing.');
  }
  await UserModel.validateUserInfo(ctx.request.body);

  // Post user.
  const userInfo = await UserModel.postUser(ctx.request.body);

  ctx.body = userInfo;
  ctx.status = 201;

  await next();

}
