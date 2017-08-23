/* /api/index.ts
   Where everything starts. */

import 'reflect-metadata';

import * as Koa from 'koa';

import { config } from './init/config';
import { initJWT } from './init/jwt';
import { initKoa } from './init/koa';

import { createConnection } from 'typeorm';
import { connectionOptions } from './init/typeorm';

console.log('Establishing database connection...');

createConnection(connectionOptions).then(async (connection) => {

  const app = new Koa();

  // Initialize everything.
  initKoa(app);
  initJWT(app);

  // Quit if port is invalid.
  if (typeof (config.api.port) !== 'number') {
    throw new Error(`Invalid PORT: ${config.api.port}`);
  }

  // Start listening!
  app.listen(config.api.port, () => {
    console.log(`Codgic-api listening at port ${config.api.port}`);
  });

}).catch((err) => {

  console.error('Database connection failed!');
  console.error(err);

});
