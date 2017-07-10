/* /api/index.ts
   Where everything starts. */

import 'reflect-metadata';

import * as Koa from 'koa';

import { getConfig } from './init/config';
import { initKoa } from './init/koa';
import { initRoutes } from './init/routes';

import { createConnection } from 'typeorm';
import { connectionOptions } from './init/typeorm';

console.log('Establishing database connection.');

createConnection(connectionOptions).then(async (connection) => {
  const app = new Koa();
  const config = getConfig();

  // Initialize everything.
  initKoa(app);
  initRoutes(app);

  // Quit if port is invalid.
  if (typeof (config.API.PORT) !== 'number') {
    console.error(`Invalid PORT: ${config.API.PORT}`);
    config.API.PORT = 8080;
    console.log('Using default PORT: 8080');
  }

  // Start listening!
  app.listen(config.API.PORT, () => {
      console.log(`Codgic-api listening at port ${config.API.PORT}`);
  });
}).catch((err) => {
  console.error('Database connection failed.');
});