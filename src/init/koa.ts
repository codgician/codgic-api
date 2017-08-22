/* /api/init/koa.ts
   Where koa gets initialized. */

import * as Koa from 'koa';
import * as bodyParser from 'koa-bodyparser';
import * as compress from 'koa-compress';
import * as logger from 'koa-logger';

import { handleKoaError } from './error';

export function initKoa(app: Koa) {

  app.use(compress());
  app.use(logger());
  app.use(bodyParser());

  app.on('error', (err: string) => {
    console.error(err);
  });

  app.use(handleKoaError);

}
