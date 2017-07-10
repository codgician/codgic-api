/* /api/controllers/user.ts
   We love our users! */

import * as Koa from 'koa';
import * as Problem from './../models/problem';

export async function getProblemList(ctx: Koa.Context, next: () => Promise<any>) {
  ctx.body = await Problem.getProblemList(ctx.query.page, ctx.query.num);
  if (!ctx.body) {
    ctx.status = 204;
  } else {
    ctx.status = 200;
  }
  await next();
}

export async function getProblemInfo(ctx: Koa.Context, next: () => Promise<any>) {
  ctx.body = await Problem.getProblemInfo(ctx.params.id);
  if (!ctx.body) {
    ctx.status = 404;
  } else {
    ctx.status = 200;
  }
  await next();
}

export async function searchProblem(ctx: Koa.Context, next: () => Promise<any>) {
  ctx.body = await Problem.searchProblem(ctx.params.query, ctx.query.page, ctx.query.num);
  if (!ctx.body) {
    ctx.status = 204;
  } else {
    ctx.status = 200;
  }
  await next();
}
